package recoverylock

import (
	"bytes"

	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

// WithdrawAddrKeeper is the part of the distribution keeper the lock needs.
type WithdrawAddrKeeper interface {
	GetDelegatorWithdrawAddr(ctx sdk.Context, delAddr sdk.AccAddress) sdk.AccAddress
	DeleteDelegatorWithdrawAddr(ctx sdk.Context, delAddr, withdrawAddr sdk.AccAddress)
}

// StakingHooks must be registered FIRST in the app's multi staking hooks,
// before the distribution hooks. Rewards are paid to the withdraw address
// whenever delegation shares change, including paths that no transaction
// controls (for example SlashRedelegation calls Unbond). For a listed
// delegator whose withdraw address is neither the wallet nor the recovery
// address, these hooks reset it to the wallet first, so the payout lands in
// the wallet where the coin rule applies. The same applies to a listed
// validator operator when its validator is deleted (commission payout). Only
// while the lock is active; otherwise they do nothing for listed wallets.
type StakingHooks struct {
	L *Lock
}

var _ stakingtypes.StakingHooks = StakingHooks{}

func (h StakingHooks) reset(ctx sdk.Context, del sdk.AccAddress) error {
	if !h.L.active(ctx) || !h.L.cfg.isListed(del) {
		return nil
	}
	w := h.L.distr.GetDelegatorWithdrawAddr(ctx, del)
	if bytes.Equal(w, del) || h.L.cfg.isRecovery(del, w) {
		return nil
	}
	h.L.distr.DeleteDelegatorWithdrawAddr(ctx, del, w)
	return nil
}

// BeforeDelegationSharesModified resets an unsafe withdraw address before the
// distribution hook withdraws rewards.
func (h StakingHooks) BeforeDelegationSharesModified(ctx sdk.Context, del sdk.AccAddress, _ sdk.ValAddress) error {
	return h.reset(ctx, del)
}

// BeforeDelegationRemoved does the same in case a later hook withdraws there.
func (h StakingHooks) BeforeDelegationRemoved(ctx sdk.Context, del sdk.AccAddress, _ sdk.ValAddress) error {
	return h.reset(ctx, del)
}

func (StakingHooks) AfterValidatorCreated(sdk.Context, sdk.ValAddress) error   { return nil }
func (StakingHooks) BeforeValidatorModified(sdk.Context, sdk.ValAddress) error { return nil }

// AfterValidatorRemoved: the distribution hook force-withdraws the removed
// validator's commission to the withdraw address of the operator account
// sdk.AccAddress(valAddr). For a listed operator, reset an unsafe withdraw
// address first, so the commission lands in the wallet.
func (h StakingHooks) AfterValidatorRemoved(ctx sdk.Context, _ sdk.ConsAddress, val sdk.ValAddress) error {
	return h.reset(ctx, sdk.AccAddress(val))
}

func (StakingHooks) AfterValidatorBonded(sdk.Context, sdk.ConsAddress, sdk.ValAddress) error {
	return nil
}

func (StakingHooks) AfterValidatorBeginUnbonding(sdk.Context, sdk.ConsAddress, sdk.ValAddress) error {
	return nil
}

func (StakingHooks) BeforeDelegationCreated(sdk.Context, sdk.AccAddress, sdk.ValAddress) error {
	return nil
}

func (StakingHooks) AfterDelegationModified(sdk.Context, sdk.AccAddress, sdk.ValAddress) error {
	return nil
}

func (StakingHooks) BeforeValidatorSlashed(sdk.Context, sdk.ValAddress, sdk.Dec) error {
	return nil
}

func (StakingHooks) AfterUnbondingInitiated(sdk.Context, uint64) error { return nil }
