package recoverylock

import (
	"bytes"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	dualstakingtypes "github.com/lavanet/lava/v5/x/dualstaking/types"
	pairingtypes "github.com/lavanet/lava/v5/x/pairing/types"
)

// checkRule runs only for a listed signer. The signer bytes come from the
// message's GetSigners, the same fields the SDK authenticates, including
// validator operator addresses for commission withdrawals.
func (l *Lock) checkRule(ctx sdk.Context, msg sdk.Msg, signer []byte) error {
	switch m := msg.(type) {
	case *banktypes.MsgSend:
		return l.checkDestination(m.ToAddress, signer, false)
	case *banktypes.MsgMultiSend:
		for _, output := range m.Outputs {
			if err := l.checkDestination(output.Address, signer, false); err != nil {
				return err
			}
		}
		return nil
	case *stakingtypes.MsgUndelegate,
		*distrtypes.MsgWithdrawDelegatorReward,
		*distrtypes.MsgWithdrawValidatorCommission,
		// Lava dualstaking unbond and provider unstake end in the staking
		// keeper's Undelegate for the signer (provider unstake only when the
		// signer is the stake entry's vault; otherwise it moves no funds).
		// Principal matures to the delegator; the distribution hook pays
		// pending rewards to the withdraw address.
		*dualstakingtypes.MsgUnbond,
		*pairingtypes.MsgUnstakeProvider:
		withdraw := l.distr.GetDelegatorWithdrawAddr(ctx, signer)
		if !bytes.Equal(withdraw, signer) && !l.cfg.isRecovery(signer, withdraw) {
			return fmt.Errorf("set the withdraw address to the wallet or its recovery address first")
		}
		return nil
	case *distrtypes.MsgSetWithdrawAddress:
		return l.checkDestination(m.WithdrawAddress, signer, true)
	case *dualstakingtypes.MsgClaimRewards:
		// Dualstaking pays claimed provider delegation rewards to the
		// delegator account itself (the signer), never to another address.
		return nil
	default:
		return fmt.Errorf("message %s is not allowed for a listed signer", sdk.MsgTypeURL(msg))
	}
}

func (l *Lock) checkDestination(destination string, signer []byte, allowSelf bool) error {
	addr, err := l.addr.StringToBytes(destination)
	if err != nil {
		return err
	}
	if l.cfg.isRecovery(signer, addr) || (allowSelf && bytes.Equal(signer, addr)) {
		return nil
	}
	return fmt.Errorf("destination %s is outside the allowed addresses for this message", destination)
}
