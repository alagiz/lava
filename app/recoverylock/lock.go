package recoverylock

import (
	"fmt"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/x/authz"
)

// MaxDepth is the maximum authz MsgExec nesting for a transaction that
// involves a listed account.
const MaxDepth = 6

var ErrLocked = errorsmod.Register("recoverylock", 1, "recovery lock")

type Lock struct {
	cfg        *Config
	addr       AddressCodec
	distr      WithdrawAddrKeeper
	lastHeight func() int64
}

// New returns the lock for cfg, or nil when cfg is nil (disabled
// configuration). The app wires no lock component for a nil Lock.
func New(cfg *Config, addr AddressCodec, distr WithdrawAddrKeeper, lastHeight func() int64) *Lock {
	if cfg == nil {
		return nil
	}
	return &Lock{cfg: cfg, addr: addr, distr: distr, lastHeight: lastHeight}
}

// ActivationHeight returns the first height with the lock.
func (l *Lock) ActivationHeight() int64 { return l.cfg.activationHeight }

// active uses the block header in consensus and the next height in CheckTx.
// The last committed height is needed when CheckTx has no header after restart.
func (l *Lock) active(ctx sdk.Context) bool {
	return l.inWindow(ctx, l.cfg.activationHeight, l.cfg.expiryTime)
}

func (l *Lock) inWindow(ctx sdk.Context, activationHeight, expiryTime int64) bool {
	height := ctx.BlockHeight()
	if ctx.IsCheckTx() {
		if height == 0 && l.lastHeight != nil {
			height = l.lastHeight()
		}
		height++
		if ctx.BlockTime().IsZero() {
			return height >= activationHeight
		}
	}
	return height >= activationHeight && (expiryTime == 0 || ctx.BlockTime().Unix() < expiryTime)
}

// checkMsg checks listed signers and records the deepest message in the tree.
// Scan past MaxDepth so a listed signer below the limit still counts.
func (l *Lock) checkMsg(ctx sdk.Context, msg sdk.Msg, depth int, deepest *int) (bool, error) {
	if depth > *deepest {
		*deepest = depth
	}
	signers, err := signersOf(msg)
	if err != nil {
		return false, sdkerrors.ErrInvalidRequest.Wrap(err.Error())
	}
	involved := false
	for _, signer := range signers {
		if !l.cfg.isListed(signer) {
			continue
		}
		involved = true
		if err := l.checkRule(ctx, msg, signer); err != nil {
			return true, ErrLocked.Wrap(err.Error())
		}
	}
	if exec, ok := msg.(*authz.MsgExec); ok {
		inner, err := exec.GetMessages()
		if err != nil {
			return involved, sdkerrors.ErrInvalidRequest.Wrap(err.Error())
		}
		for _, nested := range inner {
			listed, err := l.checkMsg(ctx, nested, depth+1, deepest)
			involved = involved || listed
			if err != nil {
				return involved, err
			}
		}
	}
	return involved, nil
}

// signersOf returns msg.GetSigners(). Legacy GetSigners implementations
// panic on an invalid address string; the panic is returned as an error.
func signersOf(msg sdk.Msg) (signers []sdk.AccAddress, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("signers of %s: %v", sdk.MsgTypeURL(msg), r)
		}
	}()
	return msg.GetSigners(), nil
}

func lockedf(format string, args ...any) error {
	return ErrLocked.Wrap(fmt.Sprintf(format, args...))
}
