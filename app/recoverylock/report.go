package recoverylock

import (
	"time"

	"github.com/cometbft/cometbft/libs/log"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestexported "github.com/cosmos/cosmos-sdk/x/auth/vesting/exported"
)

// AccountKeeper is the part of the account keeper the activation report
// reads.
type AccountKeeper interface {
	GetAccount(ctx sdk.Context, addr sdk.AccAddress) authtypes.AccountI
}

// Report logs, at the activation height only, how many listed wallets exist
// in state, how many are vesting accounts, and the latest vesting end time
// found, and logs an error line for every listed vesting account whose end
// time is not before expiry_time (its last unlocks would fall outside the
// lock). It only reads state and writes nothing, so it does not change the
// application hash. Validators compare the logged latest_vesting_end with the
// published release values.
func (l *Lock) Report(ctx sdk.Context, ak AccountKeeper, logger log.Logger) {
	if ctx.BlockHeight() != l.cfg.activationHeight || logger == nil {
		return
	}
	found, vesting, late := 0, 0, 0
	latest := int64(0)
	for _, wallet := range l.cfg.listed {
		acc := ak.GetAccount(ctx, wallet)
		if acc == nil {
			continue
		}
		found++
		va, ok := acc.(vestexported.VestingAccount)
		if !ok {
			continue
		}
		vesting++
		end := va.GetEndTime()
		if end > latest {
			latest = end
		}
		if end >= l.cfg.expiryTime {
			late++
			addr, _ := l.addr.BytesToString(wallet)
			logger.Error("recovery lock: listed vesting account ends at or after expiry_time",
				"address", addr,
				"end_time", end,
				"end_utc", time.Unix(end, 0).UTC().Format(time.RFC3339),
				"expiry_time", l.cfg.expiryTime,
			)
		}
	}
	logger.Info("recovery lock activation",
		"height", ctx.BlockHeight(),
		"listed", len(l.cfg.listed),
		"in_state", found,
		"vesting_accounts", vesting,
		"latest_vesting_end", latest,
		"latest_vesting_end_utc", time.Unix(latest, 0).UTC().Format(time.RFC3339),
		"ending_after_expiry", late,
	)
}
