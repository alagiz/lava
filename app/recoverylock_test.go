//go:build recoverylock_test

package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	tmdb "github.com/cometbft/cometbft-db"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	tmtypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	authsign "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	"github.com/cosmos/cosmos-sdk/x/bank"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/lavanet/lava/v5/app/params"
	"github.com/lavanet/lava/v5/app/recoverylock"
	commontypes "github.com/lavanet/lava/v5/utils/common/types"
	dualstakingtypes "github.com/lavanet/lava/v5/x/dualstaking/types"
	plantypes "github.com/lavanet/lava/v5/x/plans/types"
	rewardstypes "github.com/lavanet/lava/v5/x/rewards/types"
	subscriptiontypes "github.com/lavanet/lava/v5/x/subscription/types"
	"github.com/stretchr/testify/require"
)

const (
	lockDenom   = "ulava"
	lockChainID = "lock-test-1"
)

func init() {
	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")
	cfg.SetBech32PrefixForValidator(AccountAddressPrefix+"valoper", AccountAddressPrefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(AccountAddressPrefix+"valcons", AccountAddressPrefix+"valconspub")
	sdk.DefaultBondDenom = lockDenom
}

func seedKey(seed string) *secp256k1.PrivKey {
	h := sha256.Sum256([]byte(seed))
	return &secp256k1.PrivKey{Key: h[:]}
}

func addrOf(k cryptotypes.PrivKey) sdk.AccAddress { return sdk.AccAddress(k.PubKey().Address()) }

// lockAccounts: L0 base account, L1 periodic vesting, L2 continuous vesting,
// L3 delayed vesting, L4 permanent locked, all listed with recovery address
// R; fee payers P0 to P7; unlisted U and X (attacker) and C (control).
type lockAccounts struct {
	L      []*secp256k1.PrivKey
	R      *secp256k1.PrivKey
	P      []*secp256k1.PrivKey
	U, X   *secp256k1.PrivKey
	C      *secp256k1.PrivKey
	listed []byte
	params []byte
}

func newLockAccounts(t testing.TB, activation, expiry int64) lockAccounts {
	a := lockAccounts{
		R: seedKey("recoverylock-test-recovery"),
		U: seedKey("recoverylock-unlisted"),
		X: seedKey("app-test-attacker"),
		C: seedKey("app-test-control"),
	}
	for i := 0; i < 5; i++ {
		a.L = append(a.L, seedKey(fmt.Sprintf("app-test-listed-%d", i)))
	}
	for i := 0; i < 8; i++ {
		a.P = append(a.P, seedKey(fmt.Sprintf("recoverylock-test-fee-payer-%d", i)))
	}
	var b strings.Builder
	b.WriteString("# app test list\n")
	recoveries := map[string]string{}
	for _, k := range a.L {
		b.WriteString(addrOf(k).String() + "\n")
		recoveries[addrOf(k).String()] = addrOf(a.R).String()
	}
	payers := []string{}
	for _, k := range a.P {
		payers = append(payers, addrOf(k).String())
	}
	a.listed = []byte(b.String())
	sum := sha256.Sum256(a.listed)
	p, err := json.Marshal(map[string]any{
		"enabled":            true,
		"recovery_addresses": recoveries,
		"fee_payers":         payers,
		"activation_height":  activation,
		"expiry_time":        expiry,
		"list_sha256":        hex.EncodeToString(sum[:]),
		"list_count":         len(a.L),
		"test_values":        true,
	})
	require.NoError(t, err)
	a.params = p
	return a
}

type lockChain struct {
	t       testing.TB
	app     *LavaApp
	txCfg   client.TxConfig
	chainID string
	height  int64
	now     time.Time
	r       *rand.Rand
	db      tmdb.DB
	home    string
}

const (
	unbondingTime = 60 * time.Second
	blockTime     = 5 * time.Second
)

var genesisTime = time.Unix(1800000000, 0).UTC()

// newLockChain starts an app with the lock configured by accs at genesis
// time T0 with one validator.
func newLockChain(t testing.TB, accs lockAccounts, enabled bool) *lockChain {
	db := tmdb.NewMemDB()
	home := t.TempDir()
	app, encoding := openLockApp(t, db, home, accs, enabled)

	// deterministic validator key, so runs can compare app hashes
	valKey := ed25519.GenPrivKeyFromSecret([]byte("recoverylock-app-test-validator"))
	valSet := tmtypes.NewValidatorSet([]*tmtypes.Validator{tmtypes.NewValidator(valKey.PubKey(), 1)})
	big := sdk.NewCoins(sdk.NewInt64Coin(lockDenom, 1_000_000_000_000))
	t0 := genesisTime.Unix()
	vest := sdk.NewCoins(sdk.NewInt64Coin(lockDenom, 3_000_000))
	free := sdk.NewCoins(sdk.NewInt64Coin(lockDenom, 10_000_000))
	base := func(k cryptotypes.PrivKey) *authtypes.BaseAccount {
		return authtypes.NewBaseAccount(addrOf(k), nil, 0, 0)
	}
	genAccs := []authtypes.GenesisAccount{base(accs.U)}
	balances := []banktypes.Balance{{Address: addrOf(accs.U).String(), Coins: big}}
	// L0 base account
	genAccs = append(genAccs, base(accs.L[0]))
	balances = append(balances, banktypes.Balance{Address: addrOf(accs.L[0]).String(), Coins: free})
	// L1 periodic: 1/3 at T0+100s, 1/3 at T0+200s, 1/3 at T0+1e6 s
	periods := vestingtypes.Periods{
		{Length: 100, Amount: sdk.NewCoins(sdk.NewInt64Coin(lockDenom, 1_000_000))},
		{Length: 100, Amount: sdk.NewCoins(sdk.NewInt64Coin(lockDenom, 1_000_000))},
		{Length: 1_000_000, Amount: sdk.NewCoins(sdk.NewInt64Coin(lockDenom, 1_000_000))},
	}
	genAccs = append(genAccs, vestingtypes.NewPeriodicVestingAccount(base(accs.L[1]), vest, t0, periods))
	// L2 continuous over 1000 s
	genAccs = append(genAccs, vestingtypes.NewContinuousVestingAccount(base(accs.L[2]), vest, t0, t0+1000))
	// L3 delayed until T0+300 s
	genAccs = append(genAccs, vestingtypes.NewDelayedVestingAccount(base(accs.L[3]), vest, t0+300))
	// L4 permanent locked
	genAccs = append(genAccs, vestingtypes.NewPermanentLockedAccount(base(accs.L[4]), vest))
	for _, k := range accs.L[1:] {
		balances = append(balances, banktypes.Balance{Address: addrOf(k).String(), Coins: vest.Add(sdk.NewInt64Coin(lockDenom, 1_000_000))})
	}
	for _, k := range append([]*secp256k1.PrivKey{accs.R, accs.X, accs.C}, accs.P...) {
		genAccs = append(genAccs, base(k))
		balances = append(balances, banktypes.Balance{Address: addrOf(k).String(), Coins: free})
	}
	cdc := encoding.Marshaler
	genesis, err := sims.GenesisStateWithValSet(cdc, NewDefaultGenesisState(cdc), valSet, genAccs, balances...)
	require.NoError(t, err)
	var staking stakingtypes.GenesisState
	cdc.MustUnmarshalJSON(genesis[stakingtypes.ModuleName], &staking)
	staking.Params.UnbondingTime = unbondingTime
	genesis[stakingtypes.ModuleName] = cdc.MustMarshalJSON(&staking)
	state, err := json.Marshal(genesis)
	require.NoError(t, err)

	c := &lockChain{t: t, app: app, txCfg: encoding.TxConfig, chainID: lockChainID, now: genesisTime, r: rand.New(rand.NewSource(1)), db: db, home: home}
	app.InitChain(abci.RequestInitChain{
		ChainId:         c.chainID,
		Time:            genesisTime,
		ConsensusParams: sims.DefaultConsensusParams,
		AppStateBytes:   state,
	})
	c.block(blockTime) // height 1, so queries see the genesis state
	return c
}

func openLockApp(t testing.TB, db tmdb.DB, home string, accs lockAccounts, enabled bool) (*LavaApp, params.EncodingConfig) {
	if enabled {
		restore := recoverylock.UseTestConfig(accs.listed, accs.params)
		defer restore()
	}
	encoding := MakeEncodingConfig()
	opts := sims.AppOptionsMap{flags.FlagLogLevel: "error"}
	app := New(log.NewNopLogger(), db, nil, true, map[int64]bool{}, home, 0, encoding, opts, baseapp.SetChainID(lockChainID))
	require.Equal(t, enabled, app.RecoveryLock != nil)
	return app, encoding
}

func (c *lockChain) header() tmproto.Header {
	return tmproto.Header{ChainID: c.chainID, Height: c.height, Time: c.now}
}

// block runs one block at the next height, dt after the previous one, with
// the given transactions, and returns their results.
func (c *lockChain) block(dt time.Duration, txs ...[]byte) []abci.ResponseDeliverTx {
	c.height++
	c.now = c.now.Add(dt)
	c.app.BeginBlock(abci.RequestBeginBlock{Header: c.header()})
	out := make([]abci.ResponseDeliverTx, 0, len(txs))
	for _, tx := range txs {
		out = append(out, c.app.DeliverTx(abci.RequestDeliverTx{Tx: tx}))
	}
	c.app.EndBlock(abci.RequestEndBlock{Height: c.height})
	c.app.Commit()
	return out
}

// deliverCtx runs fn in a block's deliver context (between BeginBlock and
// EndBlock), as a module would.
func (c *lockChain) inBlock(dt time.Duration, fn func(ctx sdk.Context)) {
	c.height++
	c.now = c.now.Add(dt)
	c.app.BeginBlock(abci.RequestBeginBlock{Header: c.header()})
	fn(c.app.BaseApp.NewContext(false, c.header()))
	c.app.EndBlock(abci.RequestEndBlock{Height: c.height})
	c.app.Commit()
}

func (c *lockChain) query() sdk.Context {
	return c.app.BaseApp.NewContext(true, c.header())
}

func (c *lockChain) balance(k cryptotypes.PrivKey) int64 {
	return c.app.BankKeeper.GetBalance(c.query(), addrOf(k), lockDenom).Amount.Int64()
}

func (c *lockChain) spendable(k cryptotypes.PrivKey) int64 {
	return c.app.BankKeeper.SpendableCoins(c.query(), addrOf(k)).AmountOf(lockDenom).Int64()
}

type txOpt struct {
	fee     sdk.Coins
	payer   *secp256k1.PrivKey
	granter sdk.AccAddress
}

// tx signs msgs with the message signer keys (in signer order) and, when
// set, the fee payer key.
func (c *lockChain) tx(msgs []sdk.Msg, opt txOpt, signers ...*secp256k1.PrivKey) []byte {
	keys := append([]*secp256k1.PrivKey{}, signers...)
	b := c.txCfg.NewTxBuilder()
	require.NoError(c.t, b.SetMsgs(msgs...))
	fee := opt.fee
	if fee == nil {
		fee = sdk.NewCoins(sdk.NewInt64Coin(lockDenom, 5000))
	}
	b.SetFeeAmount(fee)
	b.SetGasLimit(1_000_000)
	if opt.payer != nil {
		b.SetFeePayer(addrOf(opt.payer))
		keys = append(keys, opt.payer)
	}
	if opt.granter != nil {
		b.SetFeeGranter(opt.granter)
	}
	ctx := c.query()
	mode := c.txCfg.SignModeHandler().DefaultMode()
	sigs := make([]signing.SignatureV2, len(keys))
	nums := make([]uint64, len(keys))
	for i, k := range keys {
		acc := c.app.AccountKeeper.GetAccount(ctx, addrOf(k))
		require.NotNil(c.t, acc, addrOf(k).String())
		nums[i] = acc.GetAccountNumber()
		sigs[i] = signing.SignatureV2{PubKey: k.PubKey(), Data: &signing.SingleSignatureData{SignMode: mode}, Sequence: acc.GetSequence()}
	}
	require.NoError(c.t, b.SetSignatures(sigs...))
	for i, k := range keys {
		data := authsign.SignerData{Address: addrOf(k).String(), ChainID: c.chainID, AccountNumber: nums[i], Sequence: sigs[i].Sequence, PubKey: k.PubKey()}
		bz, err := c.txCfg.SignModeHandler().GetSignBytes(mode, data, b.GetTx())
		require.NoError(c.t, err)
		sig, err := k.Sign(bz)
		require.NoError(c.t, err)
		sigs[i].Data = &signing.SingleSignatureData{SignMode: mode, Signature: sig}
	}
	require.NoError(c.t, b.SetSignatures(sigs...))
	bz, err := c.txCfg.TxEncoder()(b.GetTx())
	require.NoError(c.t, err)
	return bz
}

func (c *lockChain) check(tx []byte) abci.ResponseCheckTx {
	return c.app.CheckTx(abci.RequestCheckTx{Tx: tx, Type: abci.CheckTxType_New})
}

// run delivers tx in its own block and returns the result.
func (c *lockChain) run(tx []byte) abci.ResponseDeliverTx {
	return c.block(blockTime, tx)[0]
}

func requireOK(t *testing.T, res abci.ResponseDeliverTx, what string) {
	t.Helper()
	require.Equal(t, uint32(0), res.Code, "%s: %s", what, res.Log)
}

func requireLocked(t *testing.T, res abci.ResponseDeliverTx, contains, what string) {
	t.Helper()
	require.Equal(t, recoverylock.ErrLocked.Codespace(), res.Codespace, "%s: %s", what, res.Log)
	require.Equal(t, recoverylock.ErrLocked.ABCICode(), res.Code, "%s: %s", what, res.Log)
	require.Contains(t, res.Log, contains, what)
}

func lc(n int64) sdk.Coins { return sdk.NewCoins(sdk.NewInt64Coin(lockDenom, n)) }

func lcoin(n int64) sdk.Coin { return sdk.NewInt64Coin(lockDenom, n) }

func (c *lockChain) validator() sdk.ValAddress {
	vals := c.app.StakingKeeper.GetAllValidators(c.query())
	require.NotEmpty(c.t, vals)
	return vals[0].GetOperator()
}

// reward allocates amount (ulava, from U) as delegator rewards of the
// validator, as the distribution module does with collected fees.
func (c *lockChain) reward(from cryptotypes.PrivKey, val sdk.ValAddress, amount int64) {
	c.inBlock(blockTime, func(ctx sdk.Context) {
		require.NoError(c.t, c.app.BankKeeper.SendCoinsFromAccountToModule(ctx, addrOf(from), distrtypes.ModuleName, lc(amount)))
		v := c.app.StakingKeeper.Validator(ctx, val)
		c.app.DistrKeeper.AllocateTokensToValidator(ctx, v, sdk.NewDecCoinsFromCoins(lc(amount)...))
	})
}

func exec(grantee cryptotypes.PrivKey, msgs ...sdk.Msg) *authz.MsgExec {
	e := authz.NewMsgExec(addrOf(grantee), msgs)
	return &e
}

func TestRecoveryLockAuthzDepth(t *testing.T) {
	accs := newLockAccounts(t, 2, genesisTime.Add(time.Hour).Unix())
	active := newLockChain(t, accs, true)
	baseline := newLockChain(t, accs, false)
	wrap := func(msg sdk.Msg) sdk.Msg {
		for i := 0; i <= recoverylock.MaxDepth; i++ {
			msg = exec(accs.U, msg)
		}
		return msg
	}

	recipient := addrOf(accs.X)
	before := active.balance(accs.X)
	unlisted := wrap(banktypes.NewMsgSend(addrOf(accs.U), recipient, lc(1)))
	tx := baseline.tx([]sdk.Msg{unlisted}, txOpt{}, accs.U)
	check := active.check(tx)
	require.Zero(t, check.Code, check.Log)
	requireOK(t, baseline.run(tx), "deep unlisted exec on baseline")
	requireOK(t, active.run(tx), "deep unlisted exec with active lock")
	require.Equal(t, before+1, active.balance(accs.X))
	require.Equal(t, baseline.app.LastCommitID(), active.app.LastCommitID())

	listed := wrap(banktypes.NewMsgSend(addrOf(accs.L[0]), addrOf(accs.R), lc(1)))
	tx = active.tx([]sdk.Msg{listed}, txOpt{payer: accs.P[0]}, accs.U)
	check = active.check(tx)
	require.Equal(t, recoverylock.ErrLocked.Codespace(), check.Codespace, check.Log)
	require.Equal(t, recoverylock.ErrLocked.ABCICode(), check.Code, check.Log)
	require.Contains(t, check.Log, "nesting deeper")
	requireLocked(t, active.run(tx), "nesting deeper", "deep listed exec")
}

func TestRecoveryLockDisabledByDefault(t *testing.T) {
	app, _ := TestSetup()
	require.Nil(t, app.RecoveryLock)
}

// TestRecoveryLockAppWiring checks that no keeper or module reachable from
// the app holds the unwrapped bank keeper when the lock is enabled.
func TestRecoveryLockAppWiring(t *testing.T) {
	accs := newLockAccounts(t, 5, 4102444800)
	c := newLockChain(t, accs, true)
	_, ok := c.app.BankKeeper.(recoverylock.Bank)
	require.True(t, ok)
	baseType := reflect.TypeOf(bankkeeper.BaseKeeper{})
	// the SDK bank module needs the base keeper (see app.go)
	bankModuleType := reflect.TypeOf(bank.AppModule{})
	wrapperType := reflect.TypeOf(recoverylock.Bank{})
	seen := map[uintptr]bool{}
	var found []string
	var walk func(v reflect.Value, path string, depth int)
	walk = func(v reflect.Value, path string, depth int) {
		if depth > 12 || !v.IsValid() {
			return
		}
		switch v.Kind() {
		case reflect.Ptr:
			if v.IsNil() || seen[v.Pointer()] {
				return
			}
			seen[v.Pointer()] = true
			walk(v.Elem(), path, depth+1)
		case reflect.Interface:
			if v.IsNil() {
				return
			}
			walk(v.Elem(), path, depth+1)
		case reflect.Struct:
			if v.Type() == wrapperType || v.Type() == bankModuleType {
				return
			}
			if v.Type() == baseType {
				found = append(found, path)
				return
			}
			for i := 0; i < v.NumField(); i++ {
				walk(v.Field(i), path+"."+v.Type().Field(i).Name, depth+1)
			}
		}
	}
	// authz, group and the interchain account host share one guarded
	// dispatch router, distinct from the app's router
	router := func(v any, field string) uintptr {
		f := reflect.ValueOf(v).FieldByName(field)
		require.True(t, f.IsValid(), field)
		if f.Kind() == reflect.Interface {
			f = f.Elem()
		}
		return f.Pointer()
	}
	dispatch := router(c.app.AuthzKeeper, "router")
	require.Equal(t, dispatch, router(c.app.GroupKeeper, "router"))
	require.Equal(t, dispatch, router(c.app.ICAHostKeeper, "msgRouter"))
	require.NotEqual(t, reflect.ValueOf(c.app.MsgServiceRouter()).Pointer(), dispatch)
	walk(reflect.ValueOf(&c.app.LavaKeepers), "LavaKeepers", 0)
	walk(reflect.ValueOf(c.app.mm), "mm", 0)
	require.Empty(t, found, "holders of the unwrapped bank keeper")
}

func TestRecoveryLockApp(t *testing.T) {
	const H = 6
	accs := newLockAccounts(t, H, 4102444800)
	c := newLockChain(t, accs, true)
	L0, L1, R, X, U, P0 := accs.L[0], accs.L[1], accs.R, accs.X, accs.U, accs.P[0]
	val := c.validator()
	payer := txOpt{payer: P0}

	// Before activation, as an attacker could: withdraw address to X, authz
	// grants and a fee allowance to X, delegations of L0 and L1 (L1
	// delegates vesting coins).
	sendGrant, err := authz.NewMsgGrant(addrOf(L0), addrOf(X), authz.NewGenericAuthorization(sdk.MsgTypeURL(&banktypes.MsgSend{})), nil)
	require.NoError(t, err)
	wdGrant, err := authz.NewMsgGrant(addrOf(L0), addrOf(X), authz.NewGenericAuthorization(sdk.MsgTypeURL(&distrtypes.MsgWithdrawDelegatorReward{})), nil)
	require.NoError(t, err)
	allowance, err := feegrant.NewMsgGrantAllowance(&feegrant.BasicAllowance{}, addrOf(L0), addrOf(X))
	require.NoError(t, err)
	res := c.block(blockTime,
		c.tx([]sdk.Msg{stakingtypes.NewMsgDelegate(addrOf(L0), val, lcoin(2_000_000))}, txOpt{}, L0),
	)
	requireOK(t, res[0], "L0 delegate")
	requireOK(t, c.run(c.tx([]sdk.Msg{distrtypes.NewMsgSetWithdrawAddress(addrOf(L0), addrOf(X)), sendGrant, wdGrant, allowance}, txOpt{}, L0)), "L0 setup")
	requireOK(t, c.run(c.tx([]sdk.Msg{stakingtypes.NewMsgDelegate(addrOf(L1), val, lcoin(1_500_000))}, txOpt{}, L1)), "L1 vesting delegate")
	// control before activation: the grantee moves L0's coins
	requireOK(t, c.run(c.tx([]sdk.Msg{exec(X, banktypes.NewMsgSend(addrOf(L0), addrOf(X), lc(1)))}, txOpt{}, X)), "pre-activation exec")
	require.Equal(t, int64(H-1), c.height)

	// From H on.
	l0 := c.balance(L0)
	r := c.balance(R)

	// B: bank sends
	requireOK(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L0), addrOf(R), lc(100))}, payer, L0)), "send to recovery")
	require.Equal(t, l0-100, c.balance(L0))
	require.Equal(t, r+100, c.balance(R))
	l0 = c.balance(L0)
	toX := c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L0), addrOf(X), lc(1))}, payer, L0)
	chk := c.check(toX)
	require.Equal(t, recoverylock.ErrLocked.ABCICode(), chk.Code, chk.Log)
	requireLocked(t, c.run(toX), "outside the allowed addresses", "send to X")
	requireLocked(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L0), addrOf(R), lc(1))}, txOpt{}, L0)), "configured fee payers", "own fee")
	requireLocked(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L0), addrOf(R), lc(1))}, txOpt{payer: P0, fee: sdk.Coins{}}, L0)), "must not be zero", "zero fee")
	requireOK(t, c.run(c.tx([]sdk.Msg{&banktypes.MsgMultiSend{
		Inputs:  []banktypes.Input{{Address: addrOf(L0).String(), Coins: lc(2)}},
		Outputs: []banktypes.Output{{Address: addrOf(R).String(), Coins: lc(1)}, {Address: addrOf(R).String(), Coins: lc(1)}},
	}}, payer, L0)), "multisend to recovery")
	requireLocked(t, c.run(c.tx([]sdk.Msg{&banktypes.MsgMultiSend{
		Inputs:  []banktypes.Input{{Address: addrOf(L0).String(), Coins: lc(2)}},
		Outputs: []banktypes.Output{{Address: addrOf(R).String(), Coins: lc(1)}, {Address: addrOf(X).String(), Coins: lc(1)}},
	}}, payer, L0)), "outside the allowed addresses", "multisend mixed")
	// fee payer serves unlisted, unlisted unaffected, receiving works
	requireOK(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(U), addrOf(X), lc(1))}, txOpt{}, U)), "unlisted send")
	requireOK(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(U), addrOf(L0), lc(7))}, txOpt{}, U)), "send to listed")
	// fee grant of L0 used by X
	requireLocked(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(X), addrOf(U), lc(1))}, txOpt{granter: addrOf(L0)}, X)), "configured fee payers", "listed granter")
	// listed fee payer for an unlisted message
	requireLocked(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(U), addrOf(X), lc(1))}, txOpt{payer: L0}, U)), "configured fee payers", "listed payer")
	require.Equal(t, l0-2+7, c.balance(L0))
	l0 = c.balance(L0)

	// authz: blocked in ante, and in dispatch even when allowed and paid by a fee payer
	requireLocked(t, c.run(c.tx([]sdk.Msg{exec(X, banktypes.NewMsgSend(addrOf(L0), addrOf(X), lc(1)))}, txOpt{}, X)), "outside the allowed addresses", "exec send to X")
	dispatched := c.run(c.tx([]sdk.Msg{exec(X, banktypes.NewMsgSend(addrOf(L0), addrOf(R), lc(1)))}, payer, X))
	requireLocked(t, dispatched, "listed accounts may act only in transactions paid by a fee payer", "exec send to R with payer")
	require.Equal(t, l0, c.balance(L0))
	requireLocked(t, c.run(c.tx([]sdk.Msg{exec(X, distrtypes.NewMsgWithdrawDelegatorReward(addrOf(L0), val))}, payer, X)), "set the withdraw address", "exec withdraw")

	// distribution and staking
	xBefore := c.balance(X)
	requireLocked(t, c.run(c.tx([]sdk.Msg{distrtypes.NewMsgWithdrawDelegatorReward(addrOf(L0), val)}, payer, L0)), "set the withdraw address", "withdraw while unsafe")
	requireLocked(t, c.run(c.tx([]sdk.Msg{stakingtypes.NewMsgUndelegate(addrOf(L0), val, lcoin(1000))}, payer, L0)), "set the withdraw address", "undelegate while unsafe")
	requireLocked(t, c.run(c.tx([]sdk.Msg{distrtypes.NewMsgSetWithdrawAddress(addrOf(L0), addrOf(U))}, payer, L0)), "outside the allowed addresses", "withdraw address U")
	requireLocked(t, c.run(c.tx([]sdk.Msg{stakingtypes.NewMsgDelegate(addrOf(L0), val, lcoin(1000))}, payer, L0)), "not allowed for a listed signer", "delegate")
	requireLocked(t, c.run(c.tx([]sdk.Msg{dualstakingtypes.NewMsgDelegate(addrOf(L0).String(), val.String(), commontypes.EMPTY_PROVIDER, "", lcoin(1000))}, payer, L0)), "not allowed for a listed signer", "dualstaking delegate")
	requireLocked(t, c.run(c.tx([]sdk.Msg{subscriptiontypes.NewMsgBuy(addrOf(L0).String(), addrOf(X).String(), "free", 1, false, false)}, payer, L0)), "not allowed for a listed signer", "subscription buy")
	requireLocked(t, c.run(c.tx([]sdk.Msg{&rewardstypes.MsgFundIprpc{Creator: addrOf(L0).String(), Duration: 1, Amounts: lc(1), Spec: "LAV1"}}, payer, L0)), "not allowed for a listed signer", "fund iprpc")
	requireOK(t, c.run(c.tx([]sdk.Msg{distrtypes.NewMsgSetWithdrawAddress(addrOf(L0), addrOf(R))}, payer, L0)), "withdraw address R")
	c.reward(U, val, 1_000_000)
	r = c.balance(R)
	requireOK(t, c.run(c.tx([]sdk.Msg{distrtypes.NewMsgWithdrawDelegatorReward(addrOf(L0), val)}, payer, L0)), "withdraw rewards")
	require.Greater(t, c.balance(R), r, "rewards paid to R")
	requireOK(t, c.run(c.tx([]sdk.Msg{stakingtypes.NewMsgUndelegate(addrOf(L0), val, lcoin(1_000_000))}, payer, L0)), "undelegate")
	requireOK(t, c.run(c.tx([]sdk.Msg{dualstakingtypes.NewMsgUnbond(addrOf(L0).String(), val.String(), commontypes.EMPTY_PROVIDER, "", lcoin(500_000))}, payer, L0)), "dualstaking unbond")
	requireOK(t, c.run(c.tx([]sdk.Msg{dualstakingtypes.NewMsgClaimRewards(addrOf(L0).String(), "")}, payer, L0)), "dualstaking claim")
	require.Equal(t, xBefore, c.balance(X), "attacker got nothing")

	// matured unbonding returns to L0, then only goes to R
	l0 = c.balance(L0)
	c.block(unbondingTime + time.Second)
	c.block(blockTime)
	require.Equal(t, l0+1_500_000, c.balance(L0), "matured principal")
	requireLocked(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L0), addrOf(X), lc(1_500_000))}, payer, L0)), "outside the allowed addresses", "matured to X")
	requireOK(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L0), addrOf(R), lc(1_500_000))}, payer, L0)), "matured to R")

	// staking hook: a module path that modifies L1's shares while its
	// withdraw address is unsafe pays the rewards to L1, not to X
	c.inBlock(blockTime, func(ctx sdk.Context) {
		c.app.DistrKeeper.SetDelegatorWithdrawAddr(ctx, addrOf(L1), addrOf(X))
	})
	xBefore = c.balance(X)
	l1 := c.balance(L1)
	c.reward(U, val, 1_000_000)
	c.inBlock(blockTime, func(ctx sdk.Context) {
		shares, err := c.app.StakingKeeper.ValidateUnbondAmount(ctx, addrOf(L1), val, sdk.NewInt(1))
		require.NoError(t, err)
		_, err = c.app.StakingKeeper.Unbond(ctx, addrOf(L1), val, shares)
		require.NoError(t, err)
	})
	require.Equal(t, xBefore, c.balance(X), "hook kept rewards from X")
	require.Greater(t, c.balance(L1), l1, "rewards paid to L1")
	require.Equal(t, addrOf(L1), c.app.DistrKeeper.GetDelegatorWithdrawAddr(c.query(), addrOf(L1)))
}

func TestRecoveryLockAppVesting(t *testing.T) {
	const H = 4
	accs := newLockAccounts(t, H, 4102444800)
	c := newLockChain(t, accs, true)
	L1, L2, L3, L4, R, X := accs.L[1], accs.L[2], accs.L[3], accs.L[4], accs.R, accs.X
	payer := txOpt{payer: accs.P[1]}
	val := c.validator()
	// L1 delegates 1.5 of its 3 vesting LAVA before activation
	requireOK(t, c.run(c.tx([]sdk.Msg{stakingtypes.NewMsgDelegate(addrOf(L1), val, lcoin(1_500_000))}, txOpt{}, L1)), "L1 delegate")
	c.block(blockTime)
	require.Equal(t, int64(H), c.height+1)

	// T0+~15 s: periodic nothing vested yet beyond the free 1 LAVA (fees
	// paid by the fee payer), delayed nothing, permanent nothing.
	for _, k := range []*secp256k1.PrivKey{L1, L3, L4} {
		res := c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(k), addrOf(R), lc(1_000_001))}, payer, k))
		require.NotEqual(t, uint32(0), res.Code)
		require.NotEqual(t, recoverylock.ErrLocked.Codespace(), res.Codespace, res.Log)
		require.Contains(t, res.Log, "insufficient funds")
	}
	// after T0+100: first periodic tranche vested; to X refused, to R allowed
	c.block(100 * time.Second)
	requireLocked(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L1), addrOf(X), lc(1))}, payer, L1)), "outside the allowed addresses", "periodic to X")
	r := c.balance(R)
	spend := c.spendable(L1)
	require.Greater(t, spend, int64(1_000_000))
	requireOK(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L1), addrOf(R), lc(spend))}, payer, L1)), "periodic vested to R")
	require.Equal(t, r+spend, c.balance(R))
	// continuous: vested part to R
	spend = c.spendable(L2)
	require.Greater(t, spend, int64(1_000_000))
	requireLocked(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L2), addrOf(X), lc(spend))}, payer, L2)), "outside the allowed addresses", "continuous to X")
	requireOK(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L2), addrOf(R), lc(spend))}, payer, L2)), "continuous vested to R")
	// delayed: all vests at T0+300
	c.block(300 * time.Second)
	spend = c.spendable(L3)
	require.Equal(t, int64(4_000_000), spend)
	requireLocked(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L3), addrOf(X), lc(spend))}, payer, L3)), "outside the allowed addresses", "delayed to X")
	requireOK(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L3), addrOf(R), lc(spend))}, payer, L3)), "delayed vested to R")
	require.Equal(t, int64(0), c.balance(L3))
	// permanent locked: only the free coin moves
	requireOK(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L4), addrOf(R), lc(1_000_000))}, payer, L4)), "permanent free part")
	// periodic with delegated vesting: undelegate, matured coins return
	// with the unvested part still locked; the rest unlocks later
	requireOK(t, c.run(c.tx([]sdk.Msg{stakingtypes.NewMsgUndelegate(addrOf(L1), val, lcoin(1_500_000))}, payer, L1)), "L1 undelegate")
	c.block(unbondingTime + time.Second)
	c.block(blockTime)
	spend = c.spendable(L1)
	locked := c.balance(L1) - spend
	require.Equal(t, int64(1_000_000), locked, "third tranche still locked")
	requireLocked(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L1), addrOf(X), lc(spend))}, payer, L1)), "outside the allowed addresses", "returned to X")
	requireOK(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L1), addrOf(R), lc(spend))}, payer, L1)), "returned to R")
	// last tranche at T0+1e6
	c.block(1_000_000 * time.Second)
	require.Equal(t, int64(1_000_000), c.spendable(L1))
	requireLocked(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L1), addrOf(X), lc(1_000_000))}, payer, L1)), "outside the allowed addresses", "last tranche to X")
	requireOK(t, c.run(c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L1), addrOf(R), lc(1_000_000))}, payer, L1)), "last tranche to R")
	require.Equal(t, int64(0), c.balance(L1))
}

func TestRecoveryLockAppExpiry(t *testing.T) {
	expiry := genesisTime.Add(200 * time.Second)
	accs := newLockAccounts(t, 3, expiry.Unix())
	c := newLockChain(t, accs, true)
	L0, X := accs.L[0], accs.X
	c.block(blockTime)
	signed := c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(L0), addrOf(X), lc(1))}, txOpt{}, L0)
	x := c.balance(X)
	requireLocked(t, c.run(signed), "outside the allowed addresses", "before expiry")
	// last block before expiry
	requireLocked(t, c.block(expiry.Sub(c.now)-time.Second, signed)[0], "outside the allowed addresses", "at expiry - 1 s")
	require.Equal(t, expiry.Add(-time.Second), c.now)
	require.Equal(t, x, c.balance(X))
	// a block at or after expiry_time is unlocked
	requireOK(t, c.block(time.Second, signed)[0], "at expiry")
	require.Equal(t, x+1, c.balance(X))
}

// TestRecoveryLockAppSubscriptionRenewal: a subscription bought with auto
// renewal before activation renews from the creator's balance without any
// transaction of the creator. The coin rule refuses the renewal debit of a
// listed creator (the subscription is then removed by the module), while an
// unlisted creator's renewal is charged as usual.
func TestRecoveryLockAppSubscriptionRenewal(t *testing.T) {
	const H = 4
	accs := newLockAccounts(t, H, 4102444800)
	c := newLockChain(t, accs, true)
	L0, C, X := accs.L[0], accs.C, accs.X
	plan := plantypes.Plan{
		Index:        "lockplan",
		Description:  "plan for the lock test",
		Type:         "rpc",
		Price:        lcoin(1000),
		AllowOveruse: true,
		OveruseRate:  10,
		PlanPolicy: plantypes.Policy{
			TotalCuLimit:       100000,
			EpochCuLimit:       10000,
			MaxProvidersToPair: 3,
			GeolocationProfile: 1,
		},
		ProjectsLimit: 10,
	}
	c.inBlock(blockTime, func(ctx sdk.Context) {
		plan.Block = uint64(ctx.BlockHeight())
		require.NoError(t, c.app.PlansKeeper.AddPlan(ctx, plan, false))
	})
	// both creators buy one month with auto renewal before activation, for
	// a consumer the attacker controls
	res := c.block(blockTime,
		c.tx([]sdk.Msg{subscriptiontypes.NewMsgBuy(addrOf(L0).String(), addrOf(X).String(), "lockplan", 1, true, false)}, txOpt{}, L0),
		c.tx([]sdk.Msg{subscriptiontypes.NewMsgBuy(addrOf(C).String(), addrOf(C).String(), "lockplan", 1, true, false)}, txOpt{}, C),
	)
	requireOK(t, res[0], "L0 buy")
	requireOK(t, res[1], "C buy")
	require.Less(t, c.height, int64(H))
	l0, cb := c.balance(L0), c.balance(C)
	buy := subscriptiontypes.NewMsgBuy(addrOf(L0).String(), addrOf(accs.P[1]).String(), "lockplan", 1, true, false)
	requireLocked(t, c.run(c.tx([]sdk.Msg{buy}, txOpt{payer: accs.P[0]}, L0)), "not allowed for a listed signer", "buy a valid plan while active")
	_, found := c.app.SubscriptionKeeper.GetSubscription(c.query(), addrOf(X).String())
	require.True(t, found)
	// a month and a bit later, in several blocks (timers fire in BeginBlock)
	for i := 0; i < 5; i++ {
		c.block(7 * 24 * time.Hour)
	}
	require.Equal(t, l0, c.balance(L0), "listed creator not charged")
	require.Equal(t, cb-1000, c.balance(C), "unlisted creator charged")
	_, found = c.app.SubscriptionKeeper.GetSubscription(c.query(), addrOf(C).String())
	require.True(t, found, "control subscription renewed")
}

// TestRecoveryLockAppReplay runs the same blocks on an app without the lock
// and on one with the lock activated later than the blocks, and compares
// app hashes: before activation the lock binary computes the same state.
func TestRecoveryLockAppReplay(t *testing.T) {
	run := func(enabled bool) [][]byte {
		accs := newLockAccounts(t, 1000, 4102444800)
		c := newLockChain(t, accs, enabled)
		val := c.validator()
		L0, X := accs.L[0], accs.X
		x := c.balance(X)
		msgs := []sdk.Msg{
			stakingtypes.NewMsgDelegate(addrOf(L0), val, lcoin(1_000_000)),
			banktypes.NewMsgSend(addrOf(L0), addrOf(X), lc(5)),
			distrtypes.NewMsgSetWithdrawAddress(addrOf(L0), addrOf(X)),
		}
		var hashes [][]byte
		for _, msg := range msgs {
			requireOK(t, c.run(c.tx([]sdk.Msg{msg}, txOpt{}, L0)), sdk.MsgTypeURL(msg))
			hashes = append(hashes, bytes.Clone(c.app.LastCommitID().Hash))
		}
		require.Equal(t, x+5, c.balance(X))
		return hashes
	}
	require.Equal(t, run(false), run(true))
}

func TestRecoveryLockAppReplayAfterRestart(t *testing.T) {
	const activation = 3
	expiry := genesisTime.Add(5 * blockTime)
	accs := newLockAccounts(t, activation, expiry.Unix())
	original := newLockChain(t, accs, true)
	replay := newLockChain(t, accs, true)
	require.Equal(t, original.app.LastCommitID(), replay.app.LastCommitID())

	for _, height := range []int64{2, 3, 4, 5, 6} {
		msg := banktypes.NewMsgSend(addrOf(accs.L[0]), addrOf(accs.R), lc(1))
		// Without a separate payer the same recovery operation must be
		// refused during the window and accepted on either side of it.
		tx := original.tx([]sdk.Msg{msg}, txOpt{}, accs.L[0])
		originalResult, replayResult := original.run(tx), replay.run(tx)
		if height >= activation && original.now.Before(expiry) {
			requireLocked(t, originalResult, "configured fee payers", "recovery transfer during lock")
			requireLocked(t, replayResult, "configured fee payers", "replayed recovery transfer during lock")
		} else {
			requireOK(t, originalResult, "recovery transfer outside lock")
			requireOK(t, replayResult, "replayed recovery transfer outside lock")
		}
		require.Equal(t, height, original.height)
		require.Equal(t, original.app.LastCommitID(), replay.app.LastCommitID(), "height %d", height)

		if height == activation || replay.now.Equal(expiry) {
			commit := replay.app.LastCommitID()
			replay.app, _ = openLockApp(t, replay.db, replay.home, accs, true)
			require.Equal(t, height, replay.app.LastBlockHeight())
			require.Equal(t, commit, replay.app.LastCommitID())
		}
	}
}

// benchAccounts pads the test list to n entries.
func benchAccounts(b *testing.B, n int) lockAccounts {
	a := newLockAccounts(b, 2, 4102444800)
	var list strings.Builder
	list.WriteString("# bench list\n")
	recoveries := map[string]string{}
	for i := 0; i < n-len(a.L); i++ {
		w := addrOf(seedKey(fmt.Sprintf("recoverylock-bench-listed-%d", i)))
		r := addrOf(seedKey(fmt.Sprintf("recoverylock-bench-recovery-%d", i)))
		list.WriteString(w.String() + "\n")
		recoveries[w.String()] = r.String()
	}
	for _, k := range a.L {
		list.WriteString(addrOf(k).String() + "\n")
		recoveries[addrOf(k).String()] = addrOf(a.R).String()
	}
	payers := []string{}
	for _, k := range a.P {
		payers = append(payers, addrOf(k).String())
	}
	a.listed = []byte(list.String())
	sum := sha256.Sum256(a.listed)
	p, err := json.Marshal(map[string]any{
		"enabled": true, "recovery_addresses": recoveries, "fee_payers": payers,
		"activation_height": 2, "expiry_time": 4102444800,
		"list_sha256": hex.EncodeToString(sum[:]), "list_count": n, "test_values": true,
	})
	require.NoError(b, err)
	a.params = p
	return a
}

// BenchmarkRecoveryLockAnte runs the app's full ante handler on an ordinary
// signed bank send between unlisted accounts, with the committed (disabled)
// configuration and with a 10,000 wallet list active. Each iteration runs
// on a cache of the check state, so nothing is written.
func BenchmarkRecoveryLockAnte(b *testing.B) {
	for _, tc := range []struct {
		name    string
		enabled bool
	}{{"disabled", false}, {"active-10k", true}} {
		b.Run(tc.name, func(b *testing.B) {
			accs := benchAccounts(b, 10000)
			c := newLockChain(b, accs, tc.enabled)
			c.block(blockTime)
			bz := c.tx([]sdk.Msg{banktypes.NewMsgSend(addrOf(accs.U), addrOf(accs.X), lc(1))}, txOpt{}, accs.U)
			tx, err := c.txCfg.TxDecoder()(bz)
			require.NoError(b, err)
			ante := NewAnteHandler(c.app.AccountKeeper, c.app.BankKeeper, c.app.DualstakingKeeper, c.txCfg.SignModeHandler(),
				c.app.FeeGrantKeeper, c.app.SpecKeeper, authante.DefaultSigVerificationGasConsumer, c.app.RecoveryLock)
			base := c.app.BaseApp.NewContext(true, c.header()).WithIsCheckTx(false).WithBlockHeight(c.height + 1).WithTxBytes(bz)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ctx, _ := base.CacheContext()
				if _, err := ante(ctx.WithGasMeter(sdk.NewGasMeter(1_000_000)), tx, false); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkRecoveryLockConfig10k measures startup validation of a 10,000
// wallet list with MustConfig.
func BenchmarkRecoveryLockConfig10k(b *testing.B) {
	accs := benchAccounts(b, 10000)
	defer recoverylock.UseTestConfig(accs.listed, accs.params)()
	codec := recoverylock.AddressCodec{Prefix: AccountAddressPrefix}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if recoverylock.MustConfig(codec, nil, nil) == nil {
			b.Fatal("nil config")
		}
	}
}
