package recoverylock

import (
	"context"
	"testing"
	"time"

	"github.com/cometbft/cometbft/libs/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	crisistypes "github.com/cosmos/cosmos-sdk/x/crisis/types"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
	govv1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	govv1beta1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1beta1"
	"github.com/cosmos/cosmos-sdk/x/group"
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/gogoproto/proto"
	ibctransfertypes "github.com/cosmos/ibc-go/v7/modules/apps/transfer/types"
	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	conflicttypes "github.com/lavanet/lava/v5/x/conflict/types"
	dualstakingtypes "github.com/lavanet/lava/v5/x/dualstaking/types"
	pairingtypes "github.com/lavanet/lava/v5/x/pairing/types"
	projectstypes "github.com/lavanet/lava/v5/x/projects/types"
	rewardstypes "github.com/lavanet/lava/v5/x/rewards/types"
	subscriptiontypes "github.com/lavanet/lava/v5/x/subscription/types"
	"github.com/stretchr/testify/require"
)

func ctxAt(height int64, t time.Time, check bool) sdk.Context {
	return sdk.NewContext(nil, tmproto.Header{Height: height, Time: t}, check, log.NewNopLogger())
}

var now = time.Unix(1800000000, 0)

func coins(n int64) sdk.Coins { return sdk.NewCoins(sdk.NewInt64Coin("ulava", n)) }

func coin(n int64) sdk.Coin { return sdk.NewInt64Coin("ulava", n) }

func valoper(a sdk.AccAddress) string { return sdk.ValAddress(a).String() }

func TestActiveWindow(t *testing.T) {
	lock, _ := testLock(t)
	require.False(t, lock.active(ctxAt(19, now, false)))
	require.True(t, lock.active(ctxAt(20, now, false)))
	// CheckTx evaluates the next height
	require.True(t, lock.active(ctxAt(19, now, true)))
	require.False(t, lock.active(ctxAt(18, now, true)))
	// expiry: the first block with time at or after expiry_time is unlocked
	exp := time.Unix(lock.cfg.expiryTime, 0)
	require.True(t, lock.active(ctxAt(100, exp.Add(-time.Second), false)))
	require.False(t, lock.active(ctxAt(100, exp, false)))
	// CheckTx after restart: no header, last committed height used
	lock.lastHeight = func() int64 { return 19 }
	require.True(t, lock.active(ctxAt(0, time.Time{}, true)))
	lock.lastHeight = func() int64 { return 18 }
	require.False(t, lock.active(ctxAt(0, time.Time{}, true)))
}

func TestRules(t *testing.T) {
	lock, distr := testLock(t)
	ctx := ctxAt(25, now, false)
	L, R, X, U := bech(t, l0), bech(t, recovery), bech(t, attacker), bech(t, unlisted)
	val := valoper(unlisted)
	allowed := map[string]sdk.Msg{
		"send to recovery":       banktypes.NewMsgSend(l0, recovery, coins(1)),
		"multisend to recovery":  &banktypes.MsgMultiSend{Inputs: []banktypes.Input{{Address: L, Coins: coins(2)}}, Outputs: []banktypes.Output{{Address: R, Coins: coins(1)}, {Address: R, Coins: coins(1)}}},
		"undelegate":             stakingtypes.NewMsgUndelegate(l0, sdk.ValAddress(unlisted), coin(1)),
		"withdraw reward":        distrtypes.NewMsgWithdrawDelegatorReward(l0, sdk.ValAddress(unlisted)),
		"withdraw commission":    distrtypes.NewMsgWithdrawValidatorCommission(sdk.ValAddress(l2)),
		"withdraw addr self":     distrtypes.NewMsgSetWithdrawAddress(l0, l0),
		"withdraw addr recovery": distrtypes.NewMsgSetWithdrawAddress(l0, recovery),
		"dualstaking unbond":     dualstakingtypes.NewMsgUnbond(L, val, U, "LAV1", coin(1)),
		"dualstaking claim":      dualstakingtypes.NewMsgClaimRewards(L, ""),
		"provider unstake":       &pairingtypes.MsgUnstakeProvider{Creator: L, ChainID: "LAV1", Validator: val},
	}
	for name, msg := range allowed {
		involved, err := lock.checkMsg(ctx, msg, 0, new(int))
		require.NoError(t, err, name)
		require.True(t, involved, name)
	}
	grant := func(m sdk.Msg) *authz.MsgExec { e := authz.NewMsgExec(unlisted, []sdk.Msg{m}); return &e }
	anyOf := func(m proto.Message) *codectypes.Any {
		a, err := codectypes.NewAnyWithValue(m)
		require.NoError(t, err)
		return a
	}
	textProposal := anyOf(&govv1beta1.TextProposal{Title: "t", Description: "d"})
	vote := govv1.NewMsgVote(l0, 1, govv1.OptionYes, "")
	// The SDK validates one input per transaction. Exercise the lock's
	// signer scan directly with a second input in this unit test.
	secondSigner := &banktypes.MsgMultiSend{
		Inputs:  []banktypes.Input{{Address: U, Coins: coins(1)}, {Address: L, Coins: coins(1)}},
		Outputs: []banktypes.Output{{Address: U, Coins: coins(2)}},
	}
	blocked := map[string]sdk.Msg{
		"send to attacker":       banktypes.NewMsgSend(l0, attacker, coins(1)),
		"send to self":           banktypes.NewMsgSend(l0, l0, coins(1)),
		"send to other listed":   banktypes.NewMsgSend(l0, l1, coins(1)),
		"multisend mixed":        &banktypes.MsgMultiSend{Inputs: []banktypes.Input{{Address: L, Coins: coins(2)}}, Outputs: []banktypes.Output{{Address: R, Coins: coins(1)}, {Address: X, Coins: coins(1)}}},
		"withdraw addr attacker": distrtypes.NewMsgSetWithdrawAddress(l0, attacker),
		"fund community pool":    distrtypes.NewMsgFundCommunityPool(coins(1), l0),
		"delegate":               stakingtypes.NewMsgDelegate(l0, sdk.ValAddress(unlisted), coin(1)),
		"redelegate":             stakingtypes.NewMsgBeginRedelegate(l0, sdk.ValAddress(unlisted), sdk.ValAddress(l1), coin(1)),
		"cancel unbonding":       stakingtypes.NewMsgCancelUnbondingDelegation(l0, sdk.ValAddress(unlisted), 1, coin(1)),
		"edit validator":         stakingtypes.NewMsgEditValidator(sdk.ValAddress(l2), stakingtypes.Description{}, nil, nil),
		"unjail":                 slashingtypes.NewMsgUnjail(sdk.ValAddress(l2)),
		"gov deposit":            govv1.NewMsgDeposit(l0, 1, coins(1)),
		"gov v1beta1 deposit":    govv1beta1.NewMsgDeposit(l0, 1, coins(1)),
		"gov vote":               vote,
		"gov v1beta1 submit":     &govv1beta1.MsgSubmitProposal{Content: textProposal, InitialDeposit: coins(1), Proposer: L},
		"authz grant":            &authz.MsgGrant{Granter: L, Grantee: X},
		"authz revoke":           &authz.MsgRevoke{Granter: L, Grantee: X, MsgTypeUrl: sdk.MsgTypeURL(&banktypes.MsgSend{})},
		"authz exec as grantee": func() sdk.Msg {
			e := authz.NewMsgExec(l0, []sdk.Msg{banktypes.NewMsgSend(unlisted, attacker, coins(1))})
			return &e
		}(),
		"feegrant grant":             &feegrant.MsgGrantAllowance{Granter: L, Grantee: X},
		"feegrant revoke":            &feegrant.MsgRevokeAllowance{Granter: L, Grantee: X},
		"vesting create":             vestingtypes.NewMsgCreateVestingAccount(l0, attacker, coins(1), 0, false),
		"vesting periodic":           vestingtypes.NewMsgCreatePeriodicVestingAccount(l0, attacker, 0, nil),
		"vesting permanent":          vestingtypes.NewMsgCreatePermanentLockedAccount(l0, attacker, coins(1)),
		"crisis":                     crisistypes.NewMsgVerifyInvariant(l0, "bank", "total-supply"),
		"group create":               &group.MsgCreateGroup{Admin: L},
		"ibc transfer":               ibctransfertypes.NewMsgTransfer("transfer", "channel-0", coin(1), L, "cosmos1x", clienttypes.ZeroHeight(), 1, ""),
		"dualstaking delegate":       dualstakingtypes.NewMsgDelegate(L, val, U, "LAV1", coin(1)),
		"dualstaking redelegate":     dualstakingtypes.NewMsgRedelegate(L, U, "LAV1", X, "LAV1", coin(1)),
		"provider stake":             &pairingtypes.MsgStakeProvider{Creator: L, Validator: val, Amount: coin(1)},
		"provider move stake":        &pairingtypes.MsgMoveProviderStake{Creator: L, SrcChain: "A", DstChain: "B", Amount: coin(1)},
		"relay payment":              &pairingtypes.MsgRelayPayment{Creator: L},
		"provider freeze":            &pairingtypes.MsgFreezeProvider{Creator: L, ChainIds: []string{"A"}},
		"provider unfreeze":          &pairingtypes.MsgUnfreezeProvider{Creator: L, ChainIds: []string{"A"}},
		"subscription buy":           subscriptiontypes.NewMsgBuy(L, X, "gateway", 1, false, false),
		"subscription auto renewal":  subscriptiontypes.NewMsgAutoRenewal(L, L, "gateway", true),
		"subscription add project":   &subscriptiontypes.MsgAddProject{Creator: L},
		"subscription del project":   &subscriptiontypes.MsgDelProject{Creator: L, Name: "p"},
		"projects add keys":          &projectstypes.MsgAddKeys{Creator: L, Project: "p"},
		"projects del keys":          &projectstypes.MsgDelKeys{Creator: L, Project: "p"},
		"projects set policy":        &projectstypes.MsgSetPolicy{Creator: L, Project: "p"},
		"projects set sub policy":    &projectstypes.MsgSetSubscriptionPolicy{Creator: L},
		"rewards fund iprpc":         &rewardstypes.MsgFundIprpc{Creator: L, Duration: 1, Amounts: coins(1), Spec: "LAV1"},
		"conflict detection":         &conflicttypes.MsgDetection{Creator: L},
		"conflict vote commit":       &conflicttypes.MsgConflictVoteCommit{Creator: L},
		"conflict vote reveal":       &conflicttypes.MsgConflictVoteReveal{Creator: L},
		"nested send to attacker":    grant(banktypes.NewMsgSend(l0, attacker, coins(1))),
		"nested withdraw addr":       grant(distrtypes.NewMsgSetWithdrawAddress(l0, attacker)),
		"double nested send":         grant(grant(banktypes.NewMsgSend(l0, attacker, coins(1)))),
		"listed second signer of ms": secondSigner,
	}
	for name, msg := range blocked {
		involved, err := lock.checkMsg(ctx, msg, 0, new(int))
		require.Error(t, err, name)
		require.True(t, ErrLocked.Is(err), name)
		require.True(t, involved, name)
	}
	// withdraw address rule
	distr.withdraw[string(l0)] = attacker
	for _, msg := range []sdk.Msg{
		stakingtypes.NewMsgUndelegate(l0, sdk.ValAddress(unlisted), coin(1)),
		distrtypes.NewMsgWithdrawDelegatorReward(l0, sdk.ValAddress(unlisted)),
		dualstakingtypes.NewMsgUnbond(L, val, U, "LAV1", coin(1)),
		&pairingtypes.MsgUnstakeProvider{Creator: L, ChainID: "LAV1", Validator: val},
	} {
		_, err := lock.checkMsg(ctx, msg, 0, new(int))
		require.ErrorContains(t, err, "set the withdraw address", sdk.MsgTypeURL(msg))
	}
	distr.withdraw[string(l0)] = recovery
	_, err := lock.checkMsg(ctx, stakingtypes.NewMsgUndelegate(l0, sdk.ValAddress(unlisted), coin(1)), 0, new(int))
	require.NoError(t, err)
	distr.withdraw[string(l2)] = attacker
	_, err = lock.checkMsg(ctx, distrtypes.NewMsgWithdrawValidatorCommission(sdk.ValAddress(l2)), 0, new(int))
	require.ErrorContains(t, err, "set the withdraw address")

	// unlisted signers are not involved, whatever the message
	for _, msg := range []sdk.Msg{
		banktypes.NewMsgSend(unlisted, attacker, coins(1)),
		banktypes.NewMsgSend(unlisted, l0, coins(1)),
		stakingtypes.NewMsgDelegate(unlisted, sdk.ValAddress(unlisted), coin(1)),
		grant(banktypes.NewMsgSend(unlisted, attacker, coins(1))),
	} {
		involved, err := lock.checkMsg(ctx, msg, 0, new(int))
		require.NoError(t, err)
		require.False(t, involved)
	}
	// nested allowed message: involved, no rule error (the dispatch guard
	// refuses it later)
	involved, err := lock.checkMsg(ctx, grant(banktypes.NewMsgSend(l0, recovery, coins(1))), 0, new(int))
	require.NoError(t, err)
	require.True(t, involved)
}

func TestNestingDepth(t *testing.T) {
	lock, _ := testLock(t)
	ctx := ctxAt(25, now, false)
	decorator := Decorator{L: lock}
	wrap := func(msg sdk.Msg, levels int) sdk.Msg {
		for i := 0; i < levels; i++ {
			exec := authz.NewMsgExec(unlisted, []sdk.Msg{msg})
			msg = &exec
		}
		return msg
	}
	unlistedSend := banktypes.NewMsgSend(unlisted, attacker, coins(1))
	listedSend := banktypes.NewMsgSend(l0, recovery, coins(1))
	deepUnlisted := wrap(unlistedSend, MaxDepth+1)
	deepListed := wrap(listedSend, MaxDepth+1)
	for _, tc := range []struct {
		name           string
		msgs           []sdk.Msg
		payer, granter sdk.AccAddress
		reject         bool
	}{
		{"unlisted above cap", []sdk.Msg{deepUnlisted}, unlisted, nil, false},
		{"listed at cap", []sdk.Msg{wrap(listedSend, MaxDepth)}, payer0, nil, false},
		{"listed below cap", []sdk.Msg{deepListed}, payer0, nil, true},
		{"listed in a sibling message", []sdk.Msg{deepUnlisted, listedSend}, payer0, nil, true},
		{"listed fee payer", []sdk.Msg{deepUnlisted}, l0, nil, true},
		{"listed fee granter", []sdk.Msg{deepUnlisted}, unlisted, l0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			next := func(ctx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
				reached = true
				return ctx, nil
			}
			_, err := decorator.AnteHandle(ctx, feeTx{msgs: tc.msgs, payer: tc.payer, granter: tc.granter, fee: coins(1)}, false, next)
			if tc.reject {
				require.ErrorContains(t, err, "nesting deeper")
				require.False(t, reached)
			} else {
				require.NoError(t, err)
				require.True(t, reached)
			}
		})
	}
	require.NoError(t, lock.checkDispatched(sdk.WrapSDKContext(ctx), deepUnlisted))
	require.ErrorContains(t, lock.checkDispatched(sdk.WrapSDKContext(ctx), deepListed), "listed accounts")
}

func TestSignerPanicIsError(t *testing.T) {
	lock, _ := testLock(t)
	_, err := lock.checkMsg(ctxAt(25, now, false), &pairingtypes.MsgRelayPayment{Creator: "not an address"}, 0, new(int))
	require.True(t, sdkerrors.ErrInvalidRequest.Is(err))
}

type feeTx struct {
	msgs    []sdk.Msg
	fee     sdk.Coins
	payer   sdk.AccAddress
	granter sdk.AccAddress
}

func (f feeTx) GetMsgs() []sdk.Msg         { return f.msgs }
func (f feeTx) ValidateBasic() error       { return nil }
func (f feeTx) GetGas() uint64             { return 200000 }
func (f feeTx) GetFee() sdk.Coins          { return f.fee }
func (f feeTx) FeePayer() sdk.AccAddress   { return f.payer }
func (f feeTx) FeeGranter() sdk.AccAddress { return f.granter }

type plainTx struct{ msgs []sdk.Msg }

func (p plainTx) GetMsgs() []sdk.Msg   { return p.msgs }
func (p plainTx) ValidateBasic() error { return nil }

func TestDecorator(t *testing.T) {
	lock, _ := testLock(t)
	dec := Decorator{L: lock}
	reached := false
	next := func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) { reached = true; return ctx, nil }
	run := func(ctx sdk.Context, tx sdk.Tx) error {
		reached = false
		_, err := dec.AnteHandle(ctx, tx, false, next)
		if err == nil {
			require.True(t, reached)
		} else {
			require.False(t, reached)
		}
		return err
	}
	ctx := ctxAt(25, now, false)
	toRecovery := banktypes.NewMsgSend(l0, recovery, coins(1))
	require.NoError(t, run(ctx, feeTx{msgs: []sdk.Msg{toRecovery}, fee: coins(1), payer: payer0}))
	require.ErrorContains(t, run(ctx, feeTx{msgs: []sdk.Msg{toRecovery}, fee: coins(1), payer: l0}), "configured fee payers")
	require.ErrorContains(t, run(ctx, feeTx{msgs: []sdk.Msg{toRecovery}, fee: coins(1), payer: unlisted}), "configured fee payers")
	require.ErrorContains(t, run(ctx, feeTx{msgs: []sdk.Msg{toRecovery}, fee: coins(1), payer: payer0, granter: unlisted}), "fee grants")
	require.ErrorContains(t, run(ctx, feeTx{msgs: []sdk.Msg{toRecovery}, payer: payer0}), "must not be zero")
	require.ErrorContains(t, run(ctx, feeTx{msgs: []sdk.Msg{banktypes.NewMsgSend(l0, attacker, coins(1))}, fee: coins(1), payer: payer0}), "outside the allowed addresses")
	// unlisted with listed fee payer or granter
	other := banktypes.NewMsgSend(unlisted, attacker, coins(1))
	require.ErrorContains(t, run(ctx, feeTx{msgs: []sdk.Msg{other}, fee: coins(1), payer: l0}), "configured fee payers")
	require.ErrorContains(t, run(ctx, feeTx{msgs: []sdk.Msg{other}, fee: coins(1), payer: unlisted, granter: l0}), "configured fee payers")
	// unlisted transaction untouched, also with a fee payer account paying
	require.NoError(t, run(ctx, feeTx{msgs: []sdk.Msg{other}, fee: coins(1), payer: unlisted}))
	require.NoError(t, run(ctx, feeTx{msgs: []sdk.Msg{other}, payer: unlisted}))
	require.NoError(t, run(ctx, feeTx{msgs: []sdk.Msg{other}, fee: coins(1), payer: payer0}))
	// before activation nothing is checked
	require.NoError(t, run(ctxAt(19, now, false), feeTx{msgs: []sdk.Msg{banktypes.NewMsgSend(l0, attacker, coins(1))}, payer: l0}))
	// no fee information
	require.ErrorContains(t, run(ctx, plainTx{msgs: []sdk.Msg{toRecovery}}), "without fee information")
	require.NoError(t, run(ctx, plainTx{msgs: []sdk.Msg{other}}))
	require.NoError(t, run(ctx, plainTx{}))
}

type fakeBank struct {
	bankkeeper.Keeper
	calls int
}

func (f *fakeBank) SendCoins(sdk.Context, sdk.AccAddress, sdk.AccAddress, sdk.Coins) error {
	f.calls++
	return nil
}

func (f *fakeBank) InputOutputCoins(sdk.Context, []banktypes.Input, []banktypes.Output) error {
	f.calls++
	return nil
}

func (f *fakeBank) SendCoinsFromAccountToModule(sdk.Context, sdk.AccAddress, string, sdk.Coins) error {
	f.calls++
	return nil
}

func (f *fakeBank) DelegateCoinsFromAccountToModule(sdk.Context, sdk.AccAddress, string, sdk.Coins) error {
	f.calls++
	return nil
}

func (f *fakeBank) DelegateCoins(sdk.Context, sdk.AccAddress, sdk.AccAddress, sdk.Coins) error {
	f.calls++
	return nil
}

func (f *fakeBank) SendCoinsFromModuleToAccount(sdk.Context, string, sdk.AccAddress, sdk.Coins) error {
	f.calls++
	return nil
}

func TestBankCoinRule(t *testing.T) {
	lock, _ := testLock(t)
	inner := &fakeBank{}
	b := Bank{Keeper: inner, L: lock}
	ctx := ctxAt(25, now, false)
	L, R, X := bech(t, l0), bech(t, recovery), bech(t, attacker)
	mod := authtypes.NewModuleAddress("subscription")
	// allowed and passed through
	require.NoError(t, b.SendCoins(ctx, l0, recovery, coins(1)))
	require.NoError(t, b.SendCoins(ctx, unlisted, attacker, coins(1)))
	require.NoError(t, b.SendCoins(ctx, unlisted, l0, coins(1)))
	require.NoError(t, b.InputOutputCoins(ctx, []banktypes.Input{{Address: L, Coins: coins(1)}}, []banktypes.Output{{Address: R, Coins: coins(1)}}))
	require.NoError(t, b.SendCoinsFromAccountToModule(ctx, unlisted, "subscription", coins(1)))
	require.NoError(t, b.DelegateCoinsFromAccountToModule(ctx, unlisted, "bonded_tokens_pool", coins(1)))
	require.NoError(t, b.DelegateCoins(ctx, unlisted, mod, coins(1)))
	require.NoError(t, b.SendCoinsFromModuleToAccount(ctx, "subscription", l0, coins(1)))
	require.Equal(t, 8, inner.calls)
	// refused, nothing reaches the base keeper
	for name, err := range map[string]error{
		"send to attacker":    b.SendCoins(ctx, l0, attacker, coins(1)),
		"send to self":        b.SendCoins(ctx, l0, l0, coins(1)),
		"send to module addr": b.SendCoins(ctx, l0, mod, coins(1)),
		"multisend":           b.InputOutputCoins(ctx, []banktypes.Input{{Address: L, Coins: coins(2)}}, []banktypes.Output{{Address: R, Coins: coins(1)}, {Address: X, Coins: coins(1)}}),
		"to module":           b.SendCoinsFromAccountToModule(ctx, l0, "subscription", coins(1)),
		"fee collector":       b.SendCoinsFromAccountToModule(ctx, l1, authtypes.FeeCollectorName, coins(1)),
		"delegate":            b.DelegateCoinsFromAccountToModule(ctx, l2, "bonded_tokens_pool", coins(1)),
		"delegate coins":      b.DelegateCoins(ctx, l0, mod, coins(1)),
	} {
		require.ErrorContains(t, err, "may only go to the recovery address", name)
	}
	require.Equal(t, 8, inner.calls)
	// inactive: everything passes
	before := ctxAt(19, now, false)
	require.NoError(t, b.SendCoins(before, l0, attacker, coins(1)))
	require.NoError(t, b.SendCoinsFromAccountToModule(before, l0, "subscription", coins(1)))
	require.NoError(t, b.DelegateCoinsFromAccountToModule(before, l0, "bonded_tokens_pool", coins(1)))
	after := ctxAt(25, time.Unix(lock.cfg.expiryTime, 0), false)
	require.NoError(t, b.SendCoins(after, l0, attacker, coins(1)))
	require.Equal(t, 12, inner.calls)
}

func TestStakingHooks(t *testing.T) {
	lock, distr := testLock(t)
	h := StakingHooks{L: lock}
	ctx := ctxAt(25, now, false)
	distr.withdraw[string(l0)] = attacker
	distr.withdraw[string(l1)] = recovery
	distr.withdraw[string(unlisted)] = attacker
	require.NoError(t, h.BeforeDelegationSharesModified(ctx, l0, nil))
	require.NoError(t, h.BeforeDelegationSharesModified(ctx, l1, nil))
	require.NoError(t, h.BeforeDelegationSharesModified(ctx, unlisted, nil))
	require.Equal(t, l0, distr.GetDelegatorWithdrawAddr(ctx, l0))
	require.Equal(t, recovery, distr.GetDelegatorWithdrawAddr(ctx, l1))
	require.Equal(t, attacker, distr.GetDelegatorWithdrawAddr(ctx, unlisted))
	distr.withdraw[string(l2)] = attacker
	require.NoError(t, h.AfterValidatorRemoved(ctx, nil, sdk.ValAddress(l2)))
	require.Equal(t, l2, distr.GetDelegatorWithdrawAddr(ctx, l2))
	distr.withdraw[string(l0)] = attacker
	require.NoError(t, h.BeforeDelegationRemoved(ctx, l0, nil))
	require.Equal(t, l0, distr.GetDelegatorWithdrawAddr(ctx, l0))
	// inactive: no reset
	distr.withdraw[string(l0)] = attacker
	require.NoError(t, h.BeforeDelegationSharesModified(ctxAt(19, now, false), l0, nil))
	require.Equal(t, attacker, distr.GetDelegatorWithdrawAddr(ctx, l0))
}

// TestDispatchRouter registers the bank message service through Tee and runs
// messages through both routers.
func TestDispatchRouter(t *testing.T) {
	lock, _ := testLock(t)
	registry := codectypes.NewInterfaceRegistry()
	banktypes.RegisterInterfaces(registry)
	primary := baseapp.NewMsgServiceRouter()
	primary.SetInterfaceRegistry(registry)
	dispatch := NewDispatchRouter(registry)
	server := &countingBankServer{}
	banktypes.RegisterMsgServer(Tee{Primary: primary, Dispatch: dispatch, L: lock}, server)
	ctx := ctxAt(25, now, false)
	allowed := banktypes.NewMsgSend(l0, recovery, coins(1))
	unlistedSend := banktypes.NewMsgSend(unlisted, attacker, coins(1))

	_, err := primary.Handler(allowed)(ctx, allowed)
	require.NoError(t, err)
	require.Equal(t, 1, server.calls)
	_, err = dispatch.Handler(allowed)(ctx, allowed)
	require.ErrorContains(t, err, "listed accounts may act only in transactions paid by a fee payer")
	require.Equal(t, 1, server.calls)
	_, err = dispatch.HandlerByTypeURL(sdk.MsgTypeURL(allowed))(ctx, allowed)
	require.ErrorContains(t, err, "listed accounts may act only")
	_, err = dispatch.Handler(unlistedSend)(ctx, unlistedSend)
	require.NoError(t, err)
	require.Equal(t, 2, server.calls)
	// inactive window
	before := ctxAt(19, now, false)
	_, err = dispatch.Handler(allowed)(before, allowed)
	require.NoError(t, err)
	require.Equal(t, 3, server.calls)
}

type countingBankServer struct {
	banktypes.UnimplementedMsgServer
	calls int
}

func (s *countingBankServer) Send(context.Context, *banktypes.MsgSend) (*banktypes.MsgSendResponse, error) {
	s.calls++
	return &banktypes.MsgSendResponse{}, nil
}
