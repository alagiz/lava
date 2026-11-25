//go:build recoverylock_test

package app

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	sdked25519 "github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	crisistypes "github.com/cosmos/cosmos-sdk/x/crisis/types"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	govv1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	govv1beta1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1beta1"
	"github.com/cosmos/cosmos-sdk/x/group"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/gogoproto/proto"
	"github.com/cosmos/ibc-apps/middleware/packet-forward-middleware/v7/packetforward"
	icahosttypes "github.com/cosmos/ibc-go/v7/modules/apps/27-interchain-accounts/host/types"
	icatypes "github.com/cosmos/ibc-go/v7/modules/apps/27-interchain-accounts/types"
	ibctransfertypes "github.com/cosmos/ibc-go/v7/modules/apps/transfer/types"
	ibcclienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	ibcconnectiontypes "github.com/cosmos/ibc-go/v7/modules/core/03-connection/types"
	ibcchanneltypes "github.com/cosmos/ibc-go/v7/modules/core/04-channel/types"
	ibchost "github.com/cosmos/ibc-go/v7/modules/core/24-host"
	ibctendermint "github.com/cosmos/ibc-go/v7/modules/light-clients/07-tendermint"
	"github.com/lavanet/lava/v5/app/recoverylock"
	dualstakingtypes "github.com/lavanet/lava/v5/x/dualstaking/types"
	pairingtypes "github.com/lavanet/lava/v5/x/pairing/types"
	projectstypes "github.com/lavanet/lava/v5/x/projects/types"
	rewardstypes "github.com/lavanet/lava/v5/x/rewards/types"
	spectypes "github.com/lavanet/lava/v5/x/spec/types"
	subscriptiontypes "github.com/lavanet/lava/v5/x/subscription/types"
	"github.com/stretchr/testify/require"
)

func TestRecoveryLockAppListedMessageRejections(t *testing.T) {
	accs := newLockAccounts(t, 3, genesisTime.Add(time.Hour).Unix())
	chain := newLockChain(t, accs, true)
	listed, recipient := addrOf(accs.L[0]), addrOf(accs.X)
	val := chain.validator()
	to := recipient.String()
	from := listed.String()
	pubKey := &sdked25519.PubKey{Key: ed25519.GenPrivKeyFromSecret([]byte("recoverylock-extra-validator")).PubKey().Bytes()}
	commission := stakingtypes.NewCommissionRates(sdk.ZeroDec(), sdk.OneDec(), sdk.OneDec())
	createValidator, err := stakingtypes.NewMsgCreateValidator(
		sdk.ValAddress(listed), pubKey, lcoin(1),
		stakingtypes.Description{Moniker: "listed"}, commission, sdk.OneInt(),
	)
	require.NoError(t, err)
	expiry := genesisTime.Add(time.Hour)
	transfer := func(token sdk.Coin) sdk.Msg {
		return ibctransfertypes.NewMsgTransfer(
			"transfer", "channel-0", token, from, to,
			ibcclienttypes.ZeroHeight(), uint64(expiry.UnixNano()), "",
		)
	}
	cases := []struct {
		name string
		msg  sdk.Msg
	}{
		{"validator self-bond", createValidator},
		{"redelegate", stakingtypes.NewMsgBeginRedelegate(listed, val, sdk.ValAddress(recipient), lcoin(1))},
		{"cancel unbonding", stakingtypes.NewMsgCancelUnbondingDelegation(listed, val, 1, lcoin(1))},
		{"fund community pool", distrtypes.NewMsgFundCommunityPool(lc(1), listed)},
		{"permanent vesting", vestingtypes.NewMsgCreatePermanentLockedAccount(listed, recipient, lc(1))},
		{"periodic vesting", vestingtypes.NewMsgCreatePeriodicVestingAccount(listed, recipient, genesisTime.Unix(), vestingtypes.Periods{{Length: 60, Amount: lc(1)}})},
		{"governance deposit", govv1.NewMsgDeposit(listed, 1, lc(1))},
		{"legacy governance deposit", govv1beta1.NewMsgDeposit(listed, 1, lc(1))},
		{"crisis invariant fee", crisistypes.NewMsgVerifyInvariant(listed, "bank", "total-supply")},
		{"IBC native transfer", transfer(lcoin(1))},
		{"IBC voucher transfer", transfer(sdk.NewInt64Coin("ibc/"+strings.Repeat("A", 64), 1))},
		{"provider stake", &pairingtypes.MsgStakeProvider{Creator: from, Address: to, ChainID: "LAV1", Validator: val.String(), Amount: lcoin(1)}},
		{"relay payment", &pairingtypes.MsgRelayPayment{Creator: from}},
		{"subscription auto renewal", subscriptiontypes.NewMsgAutoRenewal(from, to, "gateway", true)},
		{"subscription delete project", &subscriptiontypes.MsgDelProject{Creator: from, Name: "project"}},
		{"project delete keys", &projectstypes.MsgDelKeys{Creator: from, Project: "project", ProjectKeys: []projectstypes.ProjectKey{{Key: to}}}},
	}
	payer := txOpt{payer: accs.P[0]}
	for _, tc := range cases {
		t.Run(tc.name+"/before", func(t *testing.T) {
			// Use a fresh CheckTx state for each signed transaction.
			pre := newLockChain(t, accs, true)
			tx := pre.tx([]sdk.Msg{tc.msg}, payer, accs.L[0])
			result := pre.check(tx)
			require.Zero(t, result.Code, result.Log)
		})
	}
	chain.block(blockTime) // The next block and CheckTx use the active rules.
	before := chain.balance(accs.L[0])
	for _, tc := range cases {
		t.Run(tc.name+"/active", func(t *testing.T) {
			tx := chain.tx([]sdk.Msg{tc.msg}, payer, accs.L[0])
			result := chain.check(tx)
			require.Equal(t, recoverylock.ErrLocked.Codespace(), result.Codespace, result.Log)
			require.Contains(t, result.Log, "not allowed for a listed signer")
			requireLocked(t, chain.run(tx), "not allowed for a listed signer", tc.name)
		})
	}
	require.Equal(t, before, chain.balance(accs.L[0]))
}

func TestRecoveryLockAppGroupDispatch(t *testing.T) {
	accs := newLockAccounts(t, 5, genesisTime.Add(time.Hour).Unix())
	member, listed, recipient := addrOf(accs.U), addrOf(accs.L[0]), addrOf(accs.R)
	for _, test := range []struct {
		name    string
		enabled bool
		want    group.ProposalExecutorResult
	}{
		{"baseline", false, group.PROPOSAL_EXECUTOR_RESULT_SUCCESS},
		{"active", true, group.PROPOSAL_EXECUTOR_RESULT_FAILURE},
	} {
		t.Run(test.name, func(t *testing.T) {
			chain := newLockChain(t, accs, test.enabled)
			create, err := group.NewMsgCreateGroupWithPolicy(
				member.String(), []group.MemberRequest{{Address: member.String(), Weight: "1"}},
				"", "", false, group.NewThresholdDecisionPolicy("1", time.Minute, 0),
			)
			require.NoError(t, err)
			requireOK(t, chain.run(chain.tx([]sdk.Msg{create}, txOpt{}, accs.U)), "create group and policy")
			policies, err := chain.app.GroupKeeper.GroupPoliciesByAdmin(
				sdk.WrapSDKContext(chain.query()), &group.QueryGroupPoliciesByAdminRequest{Admin: member.String()},
			)
			require.NoError(t, err)
			require.Len(t, policies.GroupPolicies, 1)
			policy, err := sdk.AccAddressFromBech32(policies.GroupPolicies[0].Address)
			require.NoError(t, err)
			send := banktypes.NewMsgSend(listed, recipient, lc(1))
			grant, err := authz.NewMsgGrant(listed, policy, authz.NewGenericAuthorization(sdk.MsgTypeURL(send)), nil)
			require.NoError(t, err)
			requireOK(t, chain.run(chain.tx([]sdk.Msg{grant}, txOpt{}, accs.L[0])), "grant the policy a send")

			exec := authz.NewMsgExec(policy, []sdk.Msg{send})
			submit, err := group.NewMsgSubmitProposal(
				policy.String(), []string{member.String()}, []sdk.Msg{&exec}, "",
				group.Exec_EXEC_UNSPECIFIED, "Send", "Send one coin to recovery",
			)
			require.NoError(t, err)
			requireOK(t, chain.run(chain.tx([]sdk.Msg{submit}, txOpt{}, accs.U)), "submit group proposal")
			vote := &group.MsgVote{ProposalId: 1, Voter: member.String(), Option: group.VOTE_OPTION_YES}
			requireOK(t, chain.run(chain.tx([]sdk.Msg{vote}, txOpt{}, accs.U)), "vote for group proposal")
			before := chain.balance(accs.R)
			msg := &group.MsgExec{ProposalId: 1, Executor: member.String()}
			result := chain.run(chain.tx([]sdk.Msg{msg}, txOpt{}, accs.U))
			requireOK(t, result, "deliver group execution")
			var data sdk.TxMsgData
			require.NoError(t, data.Unmarshal(result.Data))
			require.Len(t, data.MsgResponses, 1)
			var response group.MsgExecResponse
			require.NoError(t, response.Unmarshal(data.MsgResponses[0].Value))
			require.Equal(t, test.want, response.Result, result.Log)
			if test.enabled {
				require.Contains(t, result.Log, "recovery lock")
				require.Equal(t, before, chain.balance(accs.R))
			} else {
				require.Equal(t, before+1, chain.balance(accs.R))
			}
		})
	}
}

func TestRecoveryLockAppGovernanceAuthority(t *testing.T) {
	accs := newLockAccounts(t, 3, genesisTime.Add(time.Hour).Unix())
	chain := newLockChain(t, accs, true)
	chain.block(blockTime)
	proposer, listed, recipient := addrOf(accs.U), addrOf(accs.L[0]), addrOf(accs.R)
	proposal := func(from sdk.AccAddress) *govv1.MsgSubmitProposal {
		msg, err := govv1.NewMsgSubmitProposal(
			[]sdk.Msg{banktypes.NewMsgSend(from, recipient, lc(1))},
			lc(1), proposer.String(), "", "Send", "Send one coin", false,
		)
		require.NoError(t, err)
		return msg
	}
	before := chain.balance(accs.L[0])
	res := chain.run(chain.tx([]sdk.Msg{proposal(listed)}, txOpt{}, accs.U))
	require.NotZero(t, res.Code, res.Log)
	require.Contains(t, res.Log, "expected gov account as only signer for proposal message")
	require.Equal(t, before, chain.balance(accs.L[0]))

	gov := authtypes.NewModuleAddress(govtypes.ModuleName)
	requireOK(t, chain.run(chain.tx([]sdk.Msg{proposal(gov)}, txOpt{}, accs.U)), "submit proposal with governance authority")
}

func TestRecoveryLockAppICAHostDispatch(t *testing.T) {
	accs := newLockAccounts(t, 5, genesisTime.Add(time.Hour).Unix())
	chain := newLockChain(t, accs, true)
	account, listed, recipient := addrOf(accs.U), addrOf(accs.L[0]), addrOf(accs.R)
	const (
		hostPort       = icatypes.HostPortID
		controllerPort = "icacontroller-test"
		channelID      = "channel-0"
		connectionID   = "connection-0"
	)
	message := exec(accs.U, banktypes.NewMsgSend(listed, recipient, lc(1)))
	// Seed the state consumed by the host callback after IBC verifies a packet.
	chain.inBlock(blockTime, func(ctx sdk.Context) {
		chain.app.ICAHostKeeper.SetParams(ctx, icahosttypes.NewParams(true, []string{sdk.MsgTypeURL(message)}))
		chain.app.ICAHostKeeper.SetInterchainAccountAddress(ctx, connectionID, controllerPort, account.String())
		chain.app.IBCKeeper.ChannelKeeper.SetChannel(ctx, hostPort, channelID, ibcchanneltypes.Channel{
			State:          ibcchanneltypes.OPEN,
			Ordering:       ibcchanneltypes.ORDERED,
			Counterparty:   ibcchanneltypes.NewCounterparty(controllerPort, channelID),
			ConnectionHops: []string{connectionID},
			Version:        icatypes.NewDefaultMetadataString(connectionID, connectionID),
		})
	})
	grant, err := authz.NewMsgGrant(listed, account, authz.NewGenericAuthorization(sdk.MsgTypeURL(&banktypes.MsgSend{})), nil)
	require.NoError(t, err)
	requireOK(t, chain.run(chain.tx([]sdk.Msg{grant}, txOpt{}, accs.L[0])), "grant the interchain account a send")
	data, err := icatypes.SerializeCosmosTx(chain.app.AppCodec(), []proto.Message{message})
	require.NoError(t, err)
	packetData := icatypes.InterchainAccountPacketData{Type: icatypes.EXECUTE_TX, Data: data}
	packet := ibcchanneltypes.NewPacket(packetData.GetBytes(), 1, controllerPort, channelID, hostPort, channelID, ibcclienttypes.ZeroHeight(), 0)
	before := chain.balance(accs.R)
	chain.inBlock(blockTime, func(ctx sdk.Context) {
		_, err := chain.app.ICAHostKeeper.OnRecvPacket(ctx, packet)
		require.NoError(t, err)
	})
	require.Equal(t, before+1, chain.balance(accs.R))

	packet.Sequence++
	chain.inBlock(blockTime, func(ctx sdk.Context) {
		_, err := chain.app.ICAHostKeeper.OnRecvPacket(ctx, packet)
		require.ErrorContains(t, err, "recovery lock")
	})
	require.Equal(t, before+1, chain.balance(accs.R))
}

func TestRecoveryLockAppIBCTransferKeeper(t *testing.T) {
	accs := newLockAccounts(t, 3, genesisTime.Add(time.Hour).Unix())
	chain := newLockChain(t, accs, true)
	listed, sender := addrOf(accs.L[0]), addrOf(accs.U)
	const (
		port          = ibctransfertypes.PortID
		localChannel  = "channel-0"
		remoteChannel = "channel-1"
	)
	transfer := chain.app.TransferKeeper
	escrow := ibctransfertypes.GetEscrowAddress(port, localChannel)
	chain.inBlock(blockTime, func(ctx sdk.Context) {
		chain.app.IBCKeeper.ChannelKeeper.SetChannel(ctx, port, localChannel, ibcchanneltypes.Channel{
			State:        ibcchanneltypes.OPEN,
			Ordering:     ibcchanneltypes.UNORDERED,
			Counterparty: ibcchanneltypes.NewCounterparty(port, remoteChannel),
			Version:      ibctransfertypes.Version,
		})
		_, err := chain.app.ScopedTransferKeeper.NewCapability(ctx, ibchost.ChannelCapabilityPath(port, localChannel))
		require.NoError(t, err)
		require.NoError(t, chain.app.BankKeeper.SendCoins(ctx, sender, escrow, lc(2)))
		transfer.SetTotalEscrowForDenom(ctx, lcoin(2))
	})
	before := chain.balance(accs.L[0])
	denom := "uatom"
	trace := ibctransfertypes.ParseDenomTrace(ibctransfertypes.GetDenomPrefix(port, localChannel) + denom)
	voucher := trace.IBCDenom()
	chain.inBlock(blockTime, func(ctx sdk.Context) {
		incoming := ibcchanneltypes.NewPacket(nil, 1, port, remoteChannel, port, localChannel, ibcclienttypes.ZeroHeight(), 0)
		receive := ibctransfertypes.NewFungibleTokenPacketData(denom, "1", sender.String(), listed.String(), "")
		require.NoError(t, transfer.OnRecvPacket(ctx, incoming, receive))
		returning := ibctransfertypes.NewFungibleTokenPacketData(
			ibctransfertypes.GetDenomPrefix(port, remoteChannel)+lockDenom, "1", sender.String(), listed.String(), "",
		)
		require.NoError(t, transfer.OnRecvPacket(ctx, incoming, returning))

		outgoing := ibcchanneltypes.NewPacket(nil, 2, port, localChannel, port, remoteChannel, ibcclienttypes.ZeroHeight(), 0)
		nativeRefund := ibctransfertypes.NewFungibleTokenPacketData(lockDenom, "1", listed.String(), sender.String(), "")
		require.NoError(t, transfer.OnTimeoutPacket(ctx, outgoing, nativeRefund))
		voucherRefund := ibctransfertypes.NewFungibleTokenPacketData(trace.GetFullDenomPath(), "1", listed.String(), sender.String(), "")
		require.NoError(t, transfer.OnTimeoutPacket(ctx, outgoing, voucherRefund))

		// Call the keeper directly to exercise the debit guard without ante.
		for _, token := range []sdk.Coin{lcoin(1), sdk.NewInt64Coin(voucher, 1)} {
			msg := ibctransfertypes.NewMsgTransfer(
				port, localChannel, token, listed.String(), sender.String(),
				ibcclienttypes.ZeroHeight(), uint64(genesisTime.Add(time.Hour).UnixNano()), "",
			)
			_, err := transfer.Transfer(sdk.WrapSDKContext(ctx), msg)
			require.ErrorIs(t, err, recoverylock.ErrLocked)
		}
	})
	require.Equal(t, before+2, chain.balance(accs.L[0]))
	require.Equal(t, sdk.NewInt64Coin(voucher, 2), chain.app.BankKeeper.GetBalance(chain.query(), listed, voucher))
	require.Equal(t, lcoin(0), transfer.GetTotalEscrowForDenom(chain.query(), lockDenom))
}

func TestRecoveryLockAppIBCForwarding(t *testing.T) {
	accs := newLockAccounts(t, 3, genesisTime.Add(time.Hour).Unix())
	chain := newLockChain(t, accs, true)
	listed, sender := addrOf(accs.L[0]), addrOf(accs.U)
	const (
		port            = ibctransfertypes.PortID
		incomingChannel = "channel-0"
		forwardChannel  = "channel-1"
		remoteChannel   = "channel-2"
		connectionID    = "connection-0"
		clientID        = "07-tendermint-0"
	)
	ibc := chain.app.IBCKeeper
	chain.inBlock(blockTime, func(ctx sdk.Context) {
		// Seed the open outbound path and a live client for SendPacket.
		client := &ibctendermint.ClientState{
			ChainId: "lock-forward-1", LatestHeight: ibcclienttypes.NewHeight(1, 1), TrustingPeriod: time.Hour,
		}
		consensus := &ibctendermint.ConsensusState{Timestamp: ctx.BlockTime()}
		require.NoError(t, client.Initialize(ctx, chain.app.AppCodec(), ibc.ClientKeeper.ClientStore(ctx, clientID), consensus))
		ibc.ConnectionKeeper.SetConnection(ctx, connectionID, ibcconnectiontypes.ConnectionEnd{
			ClientId: clientID, State: ibcconnectiontypes.OPEN,
		})
		ibc.ChannelKeeper.SetChannel(ctx, port, forwardChannel, ibcchanneltypes.Channel{
			State:          ibcchanneltypes.OPEN,
			Ordering:       ibcchanneltypes.UNORDERED,
			Counterparty:   ibcchanneltypes.NewCounterparty(port, remoteChannel),
			ConnectionHops: []string{connectionID},
			Version:        ibctransfertypes.Version,
		})
		capabilityPath := ibchost.ChannelCapabilityPath(port, forwardChannel)
		capability, err := chain.app.ScopedIBCKeeper.NewCapability(ctx, capabilityPath)
		require.NoError(t, err)
		require.NoError(t, chain.app.ScopedTransferKeeper.ClaimCapability(ctx, capability, capabilityPath))
		ibc.ChannelKeeper.SetNextSequenceSend(ctx, port, forwardChannel, 1)
	})
	const denom = "uatom"
	voucher := ibctransfertypes.ParseDenomTrace(ibctransfertypes.GetDenomPrefix(port, incomingChannel) + denom).IBCDenom()
	receiver, err := packetforward.GetReceiver(incomingChannel, sender.String())
	require.NoError(t, err)
	intermediate, err := sdk.AccAddressFromBech32(receiver)
	require.NoError(t, err)
	memo := fmt.Sprintf(`{"forward":{"receiver":%q,"port":%q,"channel":%q}}`, listed.String(), port, forwardChannel)
	data := ibctransfertypes.NewFungibleTokenPacketData(denom, "1", sender.String(), listed.String(), memo)
	packet := ibcchanneltypes.NewPacket(data.GetBytes(), 1, port, remoteChannel, port, incomingChannel, ibcclienttypes.ZeroHeight(), 0)
	stack, found := ibc.Router.GetRoute(ibctransfertypes.ModuleName)
	require.True(t, found)
	before := chain.balance(accs.L[0])
	chain.inBlock(blockTime, func(ctx sdk.Context) {
		ack := stack.OnRecvPacket(ctx, packet, sender)
		if ack != nil {
			t.Fatalf("expected a forward with deferred acknowledgement, got %s", ack.Acknowledgement())
		}
		require.NotEmpty(t, ibc.ChannelKeeper.GetPacketCommitment(ctx, port, forwardChannel, 1))
	})
	bank := chain.app.BankKeeper
	ctx := chain.query()
	require.Equal(t, sdk.NewInt64Coin(voucher, 1), bank.GetBalance(ctx, ibctransfertypes.GetEscrowAddress(port, forwardChannel), voucher))
	require.True(t, bank.GetBalance(ctx, intermediate, voucher).IsZero())
	require.True(t, bank.GetBalance(ctx, listed, voucher).IsZero())
	require.Equal(t, before, chain.balance(accs.L[0]))
}

func TestRecoveryLockAppProviderUnstake(t *testing.T) {
	accs := newLockAccounts(t, 5, genesisTime.Add(time.Hour).Unix())
	chain := newLockChain(t, accs, true)
	vault, provider := addrOf(accs.L[0]), addrOf(accs.U)
	val := chain.validator()
	const chainID = "LAV1"
	stake := lcoin(1_000_000)
	chain.inBlock(blockTime, func(ctx sdk.Context) {
		chain.app.SpecKeeper.SetSpec(ctx, spectypes.Spec{Index: chainID, Enabled: true, MinStakeProvider: stake})
		chain.app.DualstakingKeeper.SetParams(ctx, dualstakingtypes.NewParams(stake))
	})
	initial := chain.balance(accs.L[0])
	stakeMsg := pairingtypes.NewMsgStakeProvider(vault.String(), val.String(), chainID, stake, nil, 1, 0, provider.String(), stakingtypes.Description{})
	requireOK(t, chain.run(chain.tx([]sdk.Msg{stakeMsg}, txOpt{}, accs.L[0])), "stake provider before activation")
	unsafe := distrtypes.NewMsgSetWithdrawAddress(vault, addrOf(accs.X))
	requireOK(t, chain.run(chain.tx([]sdk.Msg{unsafe}, txOpt{}, accs.L[0])), "set unsafe withdraw address before activation")

	payer := txOpt{payer: accs.P[0]}
	unstake := pairingtypes.NewMsgUnstakeProvider(vault.String(), chainID, val.String())
	requireLocked(t, chain.run(chain.tx([]sdk.Msg{stakeMsg}, payer, accs.L[0])), "not allowed for a listed signer", "stake provider while active")
	requireLocked(t, chain.run(chain.tx([]sdk.Msg{unstake}, payer, accs.L[0])), "set the withdraw address", "provider unstake with unsafe withdraw address")
	safe := distrtypes.NewMsgSetWithdrawAddress(vault, vault)
	requireOK(t, chain.run(chain.tx([]sdk.Msg{safe}, payer, accs.L[0])), "set safe withdraw address")
	requireOK(t, chain.run(chain.tx([]sdk.Msg{unstake}, payer, accs.L[0])), "unstake through the listed vault")
	unbonding, found := chain.app.StakingKeeper.GetUnbondingDelegation(chain.query(), vault, val)
	require.True(t, found)
	require.Len(t, unbonding.Entries, 1)
	require.Equal(t, stake.Amount, unbonding.Entries[0].Balance)
	chain.block(unbondingTime + time.Second)
	chain.block(blockTime)
	require.Equal(t, initial-10_000, chain.balance(accs.L[0]), "stake returns to the vault less its two pre-activation fees")

	reward := lc(500)
	chain.inBlock(blockTime, func(ctx sdk.Context) {
		require.NoError(t, chain.app.BankKeeper.SendCoinsFromAccountToModule(ctx, provider, dualstakingtypes.ModuleName, reward))
		chain.app.DualstakingKeeper.SetDelegatorReward(ctx, dualstakingtypes.DelegatorReward{
			Delegator: vault.String(), Provider: provider.String(), Amount: reward,
		})
	})
	before := chain.balance(accs.L[0])
	claim := dualstakingtypes.NewMsgClaimRewards(vault.String(), provider.String())
	requireOK(t, chain.run(chain.tx([]sdk.Msg{claim}, payer, accs.L[0])), "claim a funded provider reward")
	require.Equal(t, before+500, chain.balance(accs.L[0]))
}

func TestRecoveryLockAppIprpcFunding(t *testing.T) {
	accs := newLockAccounts(t, 4, genesisTime.Add(time.Hour).Unix())
	chain := newLockChain(t, accs, true)
	listed := addrOf(accs.L[0])
	const spec = "LAV1"
	minimum := lcoin(5)
	fund := lc(20)
	chain.inBlock(blockTime, func(ctx sdk.Context) {
		chain.app.SpecKeeper.SetSpec(ctx, spectypes.Spec{Index: spec, Enabled: true, MinStakeProvider: minimum})
		chain.app.RewardsKeeper.SetMinIprpcCost(ctx, minimum)
	})
	msg := &rewardstypes.MsgFundIprpc{Creator: listed.String(), Duration: 1, Amounts: fund, Spec: spec}
	payer := txOpt{payer: accs.P[0]}
	before := chain.balance(accs.L[0])
	requireOK(t, chain.run(chain.tx([]sdk.Msg{msg}, payer, accs.L[0])), "fund IPRPC before activation")
	require.Equal(t, before-20, chain.balance(accs.L[0]))

	requireLocked(t, chain.run(chain.tx([]sdk.Msg{msg}, payer, accs.L[0])), "not allowed for a listed signer", "fund IPRPC while active")
	chain.inBlock(blockTime, func(ctx sdk.Context) {
		err := chain.app.RewardsKeeper.FundIprpc(ctx, listed.String(), 1, fund, spec)
		require.ErrorContains(t, err, "recovery lock")
	})
	require.Equal(t, before-20, chain.balance(accs.L[0]))
}
