package recoverylock

import (
	"context"

	"github.com/cosmos/cosmos-sdk/baseapp"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	gogogrpc "github.com/cosmos/gogoproto/grpc"
	"google.golang.org/grpc"
)

// Bank wraps the app's bank keeper and applies the coin rule: while the lock
// is active, coins leaving a listed address may only go to its registered
// recovery address. SDK v0.47 has no send restriction hook, so the app
// replaces its bank keeper (the bankkeeper.Keeper interface held in
// LavaKeepers.BankKeeper) with this wrapper right after creating it, before
// any consumer receives it. The SDK bank module retains the base keeper
// for its migrations. Ante and dispatch guard its MsgSend and MsgMultiSend
// handlers. The wrapper checks fee deduction, staking delegation,
// distribution, governance deposits, IBC transfer escrow and burn,
// packet forwarding, vesting account creation, crisis, and the Lava modules
// (subscription purchases and automatic renewals, IPRPC funding,
// dualstaking and pairing stake through staking).
//
// Only the five methods that debit an account are overridden. The base
// keeper's own composite methods (for example SendCoinsFromAccountToModule,
// which calls SendCoins on the base keeper) are overridden as a whole, so no
// debit reaches the base keeper without passing the rule. Module to account
// and module to module transfers are credits or module bookkeeping and pass
// unchanged.
type Bank struct {
	bankkeeper.Keeper
	L *Lock
}

var _ bankkeeper.Keeper = Bank{}

func (b Bank) refuse(ctx sdk.Context, from, to sdk.AccAddress) error {
	l := b.L
	if !l.active(ctx) || !l.cfg.isListed(from) {
		return nil
	}
	if to != nil && l.cfg.isRecovery(from, to) {
		return nil
	}
	return lockedf("coins of %s may only go to the recovery address", from)
}

// SendCoins applies the coin rule to a direct account to account transfer.
func (b Bank) SendCoins(ctx sdk.Context, from, to sdk.AccAddress, amt sdk.Coins) error {
	if err := b.refuse(ctx, from, to); err != nil {
		return err
	}
	return b.Keeper.SendCoins(ctx, from, to, amt)
}

// InputOutputCoins applies the coin rule to every listed input: every
// output must be that input's recovery address.
func (b Bank) InputOutputCoins(ctx sdk.Context, inputs []banktypes.Input, outputs []banktypes.Output) error {
	l := b.L
	if l.active(ctx) {
		for _, in := range inputs {
			from, err := l.addr.StringToBytes(in.Address)
			if err != nil {
				return err
			}
			if !l.cfg.isListed(from) {
				continue
			}
			for _, out := range outputs {
				to, err := l.addr.StringToBytes(out.Address)
				if err != nil {
					return err
				}
				if err := b.refuse(ctx, from, to); err != nil {
					return err
				}
			}
		}
	}
	return b.Keeper.InputOutputCoins(ctx, inputs, outputs)
}

// SendCoinsFromAccountToModule refuses a listed source: a module account is
// never a recovery address (checked at startup).
func (b Bank) SendCoinsFromAccountToModule(ctx sdk.Context, from sdk.AccAddress, module string, amt sdk.Coins) error {
	if err := b.refuse(ctx, from, nil); err != nil {
		return err
	}
	return b.Keeper.SendCoinsFromAccountToModule(ctx, from, module, amt)
}

// DelegateCoinsFromAccountToModule refuses a listed delegator. It is the
// staking keeper's debit for every delegation, including dualstaking and
// pairing stake, which call the staking keeper's Delegate.
func (b Bank) DelegateCoinsFromAccountToModule(ctx sdk.Context, from sdk.AccAddress, module string, amt sdk.Coins) error {
	if err := b.refuse(ctx, from, nil); err != nil {
		return err
	}
	return b.Keeper.DelegateCoinsFromAccountToModule(ctx, from, module, amt)
}

// DelegateCoins refuses a listed delegator.
func (b Bank) DelegateCoins(ctx sdk.Context, from, moduleAcc sdk.AccAddress, amt sdk.Coins) error {
	if err := b.refuse(ctx, from, nil); err != nil {
		return err
	}
	return b.Keeper.DelegateCoins(ctx, from, moduleAcc, amt)
}

// NewDispatchRouter returns the message router for keepers that dispatch
// messages on behalf of other accounts (authz, group, interchain account
// host). In SDK v0.47 authz and group take the concrete
// *baseapp.MsgServiceRouter, so the lock uses a second router of that type.
// The app registers every message service in both routers through Tee; the
// dispatch router's handlers first refuse every message that has a listed
// signer at any depth while the lock is active, then run the same service
// implementation as the app's router.
//
// Dispatch has no fee payer: with an authz grant made before activation, a
// group policy, an interchain account or any grantee could otherwise run
// allowed messages as a listed wallet without the recovery operator (for
// example set the withdraw address and withdraw rewards to it, or fill the
// unbonding entries with tiny undelegations). Listed wallets therefore act
// only in top level messages of transactions that pass the Decorator.
// Messages without a listed signer at any depth pass if their signers and
// wrapped messages can be decoded.
func NewDispatchRouter(registry codectypes.InterfaceRegistry) *baseapp.MsgServiceRouter {
	r := baseapp.NewMsgServiceRouter()
	r.SetInterfaceRegistry(registry)
	return r
}

// Tee registers each message service in Primary unchanged and in Dispatch
// with the lock check in front of every method. The app passes it to the
// module configurator as the message server.
type Tee struct {
	Primary  gogogrpc.Server
	Dispatch gogogrpc.Server
	L        *Lock
}

var _ gogogrpc.Server = Tee{}

// RegisterService implements gogogrpc.Server.
func (t Tee) RegisterService(sd *grpc.ServiceDesc, impl interface{}) {
	t.Primary.RegisterService(sd, impl)
	t.Dispatch.RegisterService(t.L.guardService(sd), impl)
}

// guardService copies sd and wraps every method handler. MsgServiceRouter
// calls a method handler with an interceptor that ignores the decoded
// request and passes the routed message to the unary handler; the wrapper
// checks that message, with the sdk.Context the router placed in the Go
// context, before the service implementation runs. When MsgServiceRouter
// probes a method at registration (its interceptor does not call the
// handler), nothing is checked.
func (l *Lock) guardService(sd *grpc.ServiceDesc) *grpc.ServiceDesc {
	guarded := *sd
	guarded.Methods = make([]grpc.MethodDesc, len(sd.Methods))
	for i, method := range sd.Methods {
		inner := method.Handler
		guarded.Methods[i] = grpc.MethodDesc{
			MethodName: method.MethodName,
			Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
				if interceptor == nil {
					return inner(srv, ctx, dec, nil)
				}
				return inner(srv, ctx, dec, func(ictx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
					return interceptor(ictx, req, info, func(hctx context.Context, routed interface{}) (interface{}, error) {
						if err := l.checkDispatched(hctx, routed); err != nil {
							return nil, err
						}
						return handler(hctx, routed)
					})
				})
			},
		}
	}
	return &guarded
}

// checkDispatched refuses a dispatched message with a listed signer at any
// depth while the lock is active.
func (l *Lock) checkDispatched(goCtx context.Context, routed interface{}) error {
	msg, ok := routed.(sdk.Msg)
	if !ok {
		return lockedf("dispatched request %T is not a message", routed)
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	if !l.active(ctx) {
		return nil
	}
	var deepest int
	involved, err := l.checkMsg(ctx, msg, 0, &deepest)
	if err != nil {
		return err
	}
	if involved {
		return lockedf("listed accounts may act only in transactions paid by a fee payer")
	}
	return nil
}

// Decorator is the ante decorator. Place it before any fee deduction and
// before signature verification. BaseApp discards ante state on error.
type Decorator struct{ L *Lock }

// AnteHandle rejects a transaction that involves a listed address (as signer
// of a message at any depth, as fee payer or as fee granter) unless every
// message with a listed signer is allowed and the fee is paid by the
// configured fee payer set, without a fee granter, and is not zero.
func (d Decorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	l := d.L
	if !l.active(ctx) {
		return next(ctx, tx, simulate)
	}
	msgs := tx.GetMsgs()
	if len(msgs) == 0 {
		// Nothing to check, and FeePayer() would panic on an empty signer
		// list. baseapp refuses transactions without messages before the
		// ante handler runs.
		return next(ctx, tx, simulate)
	}
	involved := false
	var deepest int
	for _, m := range msgs {
		sub, err := l.checkMsg(ctx, m, 0, &deepest)
		if err != nil {
			return ctx, err
		}
		involved = involved || sub
	}
	feeTx, ok := tx.(sdk.FeeTx)
	if !ok {
		if involved {
			return ctx, lockedf("transaction without fee information")
		}
		return next(ctx, tx, simulate)
	}
	payer, granter := feeTx.FeePayer(), feeTx.FeeGranter()
	if l.cfg.isListed(payer) || l.cfg.isListed(granter) {
		involved = true
	}
	if involved {
		if deepest > MaxDepth {
			return ctx, lockedf("message nesting deeper than %d", MaxDepth)
		}
		if !l.cfg.isFeePayer(payer) {
			return ctx, lockedf("fee must be paid by one of the configured fee payers")
		}
		if len(granter) != 0 {
			return ctx, lockedf("fee grants are not allowed")
		}
		if feeTx.GetFee().IsZero() {
			return ctx, lockedf("fee must not be zero")
		}
	}
	return next(ctx, tx, simulate)
}
