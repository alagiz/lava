# Recovery lock for lava-mainnet-1

The implementation is based on Lava v6.2.4 at commit `e293c30dbd5fc56821b526bb0cd43ecf49605f35`, with the Lava Cosmos SDK fork `github.com/lavanet/cosmos-sdk v0.47.13-lava-cosmos`, IBC Go `v7.4.0`, packet forward middleware `v7.1.3` and CometBFT `v0.37.5`.

## What it is

A compiled allow-list for a coordinated halt-height upgrade. From `activation_height`, the wallets in the list may only move funds to their registered recovery address, in transactions whose fee is paid by one of the configured fee payer accounts. Everything else signed by or debiting a listed wallet is refused. The lock caps authz nesting at six levels for transactions involving a listed signer, fee payer or fee granter. Unlisted transactions keep the ordinary Lava depth behavior. There is no new store, no migration, no upgrade plan, no state change at activation and no change to any Lava module: all changes are in the app wiring and the new package `app/recoverylock`. The upgrade moves no funds.

The lock activates for all listed wallets at the upgrade height and covers scheduled vesting. Every vesting unlock and every completed unbonding lands in the listed wallet, where it can only be sent to the wallet's recovery address. The release rules require `expiry_time` to be at least two unbonding periods plus seven days after the later of estimated activation and the latest listed vesting end (`latest_vesting_end`), and the node logs the latest vesting end it finds in state at the activation height.

The window is inclusive at `activation_height` and ends at the first block whose header time is at or after `expiry_time` (Unix seconds). CheckTx evaluates the next height and falls back to the last committed height plus one when its context has no height; with an unknown CheckTx block time it applies the height condition alone. Before activation and after expiry every lock component is a no-op, so the binary executes those blocks exactly like the base release for the same inputs.

In SDK v0.47, `Commit` in `baseapp/abci.go` saves application state before calling `halt()`. So validators set `halt-height = activation_height - 1`: every node executes the last block before activation on the base binary and the lock binary executes `activation_height` itself. With `halt-height = activation_height` the block at that height would run on the base binary everywhere while the lock binary would run it with the lock, and a node replaying the chain from genesis could disagree on that block.

The committed configuration is disabled. A binary built from this commit as it is wires none of the lock components and runs exactly like the base release. A release for the real incident fills in the list and sets `"enabled": true`.

A listed wallet must sign its recovery messages at the top level. The transaction must pay a positive fee from a configured fee payer and have an empty fee granter. Setting the transaction's `Fee.Payer` field makes the SDK require the fee payer's signature in addition to the message signers. A listed wallet's balance cannot fund fees, including fees for a different signer using an older allowance. Transactions with no listed signer at any authz depth and with an unlisted fee payer and fee granter follow the ordinary ante rules for nesting. If the current withdraw address is unsafe, confirm a separate `MsgSetWithdrawAddress` transaction before submitting a withdrawal or undelegation. Ante reads the stored address before executing any message in the transaction. When the wallet and the fee payer sign one after the other with the CLI (`tx sign`), use `--sign-mode amino-json`: a `SIGN_MODE_DIRECT` signature covers all signer infos, so a signer info added by the second `tx sign` invalidates the first signature. Tools that set both signer infos before signing can use direct mode (the app tests do).

## Layout

| Path | Content |
| --- | --- |
| [`app/recoverylock/config.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/config.go) | Embedded `listed.txt` and [`params.json`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/params.json), strict parsing, startup validation including the vesting expiry bounds, the disabled state, `MustConfig`, the bech32 address codec. |
| [`app/recoverylock/json.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/json.go) | Strict JSON decoding (duplicate keys, trailing data). |
| [`app/recoverylock/lock.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/lock.go) | `Lock`, the active window, message checks with the authz depth bound, `ErrLocked` (codespace `recoverylock`, code 1). |
| [`app/recoverylock/rules.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/rules.go) | The allow-list for listed signers (bank, distribution, staking, dualstaking unbond and claim, provider unstake). |
| [`app/recoverylock/components.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/components.go) | The coin rule (`Bank`, a wrapper of the bank keeper), the dispatch router and its registration (`NewDispatchRouter`, `Tee`), the ante decorator. |
| [`app/recoverylock/hooks.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/hooks.go) | Staking hooks that reset an unsafe withdraw address before automatic payouts. |
| [`app/recoverylock/report.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/report.go) | The activation report: at `activation_height` the node logs the listed vesting accounts it finds in state and their latest end time (reads only). |
| [`app/recoverylock/testbuild_on.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/testbuild_on.go), [`testbuild_off.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/testbuild_off.go) | Selected by the build tag `recoverylock_test` (tests and local test chains only): the `testBuild` constant and, in tagged builds only, `UseTestConfig`. Untagged builds contain no configuration override. |
| [`app/recoverylock/listed.txt`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/listed.txt), [`params.json`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/params.json) | The committed configuration: disabled, no entries. |
| [`app/recoverylock/mainnet-wallets.json`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/mainnet-wallets.json) | Review manifest with a test wallet and placeholders. |
| [`app/recoverylock/testdata/listed.txt`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/testdata/listed.txt), [`testdata/params.json`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/testdata/params.json) | Test values (3 listed wallets, 1 recovery address, 8 fee payers, public placeholder keys) used by the tests and for local chains. |
| [`app/ante.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/ante.go), [`app/app.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/app.go) | Wiring (see Wiring). |
| `app/recoverylock/*_test.go`, [`app/recoverylock_test.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock_test.go), [`app/recoverylock_value_paths_test.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock_value_paths_test.go) | Unit and app tests, benchmarks. [`config_test.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/config_test.go) and [`lock_test.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/lock_test.go) run in a plain `go test ./...`. The tagged config and app tests need `-tags recoverylock_test`. |
| [`.github/workflows/lava.yml`](https://github.com/alagiz/lava/blob/recovery-lock/.github/workflows/lava.yml) | One added step that runs the tagged lock tests in the consensus test job. |

## Configuration

The affected wallets, recovery address and fee payer will be provided separately once the Lava team is open to this kind of change. Replace the entire wallet array (including the test wallet) and both address fields in the [release manifest](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/mainnet-wallets.json) before staging a release. The manifest order defines the count and SHA-256 input, with one address and a newline per line.

Stage the files from the repository root with `SETTINGS` set to the approved JSON object containing `activation_height`, `expiry_time`, `activation_time_estimate`, `estimate_ref_height`, `estimate_ref_time`, `unbonding_seconds` and `latest_vesting_end`.

```bash
set -euo pipefail
lock_dir=app/recoverylock
manifest="$lock_dir/mainnet-wallets.json"
jq -e '
  def address: type == "string" and startswith("lava@1");
  .chain_id == "lava-mainnet-1"
  and (.recovery_address | address)
  and (.fee_payer_address | address)
  and (.wallets | type == "array" and length > 0 and all(.[]; address))
' "$manifest" >/dev/null
jq -er '.wallets[]' "$manifest" > "$lock_dir/listed.txt"
list_count=$(wc -l < "$lock_dir/listed.txt")
list_hash=$(sha256sum "$lock_dir/listed.txt" | cut -d ' ' -f 1)
jq --slurpfile manifest "$manifest" --argjson count "$list_count" --arg hash "$list_hash" '
  $manifest[0] as $m
  | .enabled = true
  | .list_count = $count
  | .list_sha256 = $hash
  | .recovery_addresses = (reduce $m.wallets[] as $wallet ({}; .[$wallet] = $m.recovery_address))
  | .fee_payers = [$m.fee_payer_address]
  | .test_values = false
' "$SETTINGS" > "$lock_dir/params.json"
wc -l "$lock_dir/listed.txt"
sha256sum "$lock_dir/listed.txt" "$lock_dir/params.json"
```

[`app/recoverylock/listed.txt`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/listed.txt) holds one listed account per line. Blank lines and lines starting with `#` (after whitespace) are ignored. [`app/recoverylock/params.json`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/params.json) is parsed strictly: unknown, duplicate or wrong-case keys, incompatible non-null value types and trailing data are refused.

Committed (disabled) state:

```json
{
  "enabled": false
}
```

with a `listed.txt` that has no entries (comments only). `"enabled": false` requires every other field to decode to its zero value and the list to be empty, so a real list with `enabled` left false makes the node refuse to start instead of running without the lock. With the disabled configuration `MustConfig` returns nil, logs `recovery lock disabled params_sha256=...`, and the app wires no lock component: no ante decorator, no bank wrapper, no dispatch router, no staking hooks, no activation report.

Enabled state fields:

| Field | Meaning |
| --- | --- |
| `enabled` | `true` |
| `recovery_addresses` | Object keyed by the canonical listed address, one recovery address per listed wallet. Several wallets may share a recovery address. A recovery address cannot be a listed wallet. |
| `fee_payers` | 1 to 16 distinct addresses outside the listed wallet set. A fee payer may be the recovery address. |
| `activation_height` | First height with the lock. Validators halt one block earlier (`halt-height = activation_height - 1`, see What it is). |
| `expiry_time` | Unix seconds. The lock is off from the first block with header time at or after it. |
| `latest_vesting_end` | Unix seconds, the latest `end_time` of any vesting account in the list, read from chain state when the list is built; 0 when no listed wallet is a vesting account. Required in release builds. |
| `list_count`, `list_sha256` | Count and sha256 of the raw bytes of `listed.txt`. |
| `test_values` | Must be `false` in a release build. |
| `activation_time_estimate`, `estimate_ref_height`, `estimate_ref_time`, `unbonding_seconds` | Release cross-checks, below. |

At startup every build checks the list digest and count, requires a nonempty list with unique address bytes, and enforces the recovery address and fee payer rules above. Every address must decode to a 20-byte `lava@` bech32 address outside the module accounts, so placeholders cause startup to fail. Every untagged startup also applies the following checks.

- `test_values` false and none of the known test addresses (the public placeholder keys of `testdata/`);
- `unbonding_seconds` between 1814400 (21 days) and one year;
- a mainnet reference block (`estimate_ref_height`, `estimate_ref_time`) below the activation height with an implied block time between 5 s and 30 s up to `activation_time_estimate`;
- `latest_vesting_end` present and nonnegative, with enough time before the absolute cap for two unbonding periods and seven days;
- minimum `expiry_time` of `max(activation_time_estimate, latest_vesting_end) + 2 x unbonding_seconds + 7 days`;
- maximum `expiry_time` of one year (365 days) after the minimum, capped at 1096 days (three years) after `activation_time_estimate`.

The attacker can fill the unbonding entries of a delegation (50 per pair on lava-mainnet-1). Allow one period for those entries to clear and another for the recovery operator's undelegation to complete, counted from the later of estimated activation and the last listed vesting end. The seven-day margin allows the operator to send the recovered coins while the lock is active. The one-year upper bound is measured from the minimum expiry because two supported unbonding periods plus seven days can exceed one year. Any failed check panics at startup with `recovery lock config: <reason>`, so a node with a bad list does not start.

To estimate the release time, take the latest block (height h0, time t0; these are `estimate_ref_height` and `estimate_ref_time`) and the block 10000 heights earlier (time t1); average block time b = (t0 - t1) / 10000; estimate = t0 + (H - h0) x b rounded up to the hour; use the later of this and the planned halt time. Use the live staking `unbonding_time` for `unbonding_seconds`. For `latest_vesting_end`, query every listed address on the deployment release and take the largest `end_time` of the vesting accounts.

At startup an enabled binary logs `recovery lock config` with `mode` (`release` or `test`), `activation_height`, `expiry_time`, `expiry_utc`, `latest_vesting_end`, `recovery_count`, `params_sha256`, `fee_payers`, `list_count` and `list_sha256`. Publish the sha256 of both files with the release so validators can compare them with that line. At the activation height it logs `recovery lock activation` with the number of listed wallets found in state, how many are vesting accounts, the latest vesting end found and the number ending at or after `expiry_time` (one `ERR` line per such account). The activation report reads state. The startup expiry checks use the embedded timestamp, so compare it with deployment chain state before building the release.

### Why the committed configuration is disabled

The repository's own CI ([`.github/workflows/lava.yml`](https://github.com/alagiz/lava/blob/recovery-lock/.github/workflows/lava.yml): `go test ./utils/...`, `./protocol/common/... ./testutil/common/... ./cmd/common/...`, `./x/... ./app/...`, the protocol and e2e jobs) builds without any extra tag. With the committed disabled configuration a plain build, a plain `go test ./...` and every CI target run the app exactly as the base release, with the upstream rules. Tests that need the lock are built with `-tags recoverylock_test` and call `recoverylock.UseTestConfig(listed, params)` before building the app; `UseTestConfig` exists only in builds with that tag ([`testbuild_on.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/testbuild_on.go)), so an untagged build, including every release, has no way to inject a configuration. The release-rule tests ([`config_test.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/config_test.go)) and the rule tests ([`lock_test.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/lock_test.go)) need no tag. One step added to the consensus test job of [`.github/workflows/lava.yml`](https://github.com/alagiz/lava/blob/recovery-lock/.github/workflows/lava.yml) runs `./app/` and `./app/recoverylock/` again with `-tags recoverylock_test`. A release replaces `listed.txt` and [`params.json`](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/params.json) with the real data (`"enabled": true`, `"test_values": false`) and is built with the normal release process and no extra tag; that build refuses test values and the known test addresses at startup.

## Message paths

| Path | Behavior while active | Coverage |
| --- | --- | --- |
| Bank send and multisend | Each listed input may pay only its own recovery address. The wallet and a configured fee payer sign. | App transactions |
| Fee deduction and fee grants | A listed account cannot pay fees or fund an existing allowance. Recovery transactions require a positive fee and an empty fee granter. | App transactions |
| Staking delegate, redelegate, create validator and cancel unbonding | Refused. The bank wrapper also refuses delegation debits, including those initiated by Lava keepers. | Rule and app tests |
| Staking undelegate and unbonding completion | A co-signed undelegation is allowed after checking the withdraw address. Matured coins return to the wallet and retain any unvested lock. | App transactions |
| Distribution | Set the withdraw address to self or recovery before withdrawing delegation rewards or validator commission. A delegation change resets any other stored withdraw address to self before distribution can pay it. | App transactions, hook tests |
| Authz, group and ICA host dispatch | A listed signer at any depth makes the dispatched message fail. A fee payer cannot use a pre-existing grant to impersonate a listed signer. | Authz execution, signed group proposal execution and an ICA host packet fixture |
| Governance and crisis | Listed votes and deposits are refused. The bank wrapper rejects listed debits to module accounts. SDK governance proposal dispatch requires the governance module account as signer. | Rule tests and a signed governance authority test |
| IBC and packet forwarding | Listed outbound transfers are refused, including native escrow and voucher debits. Incoming credits and refunds use ordinary module paths. | App tests for both debit branches, credits, timeout refunds and a forwarded packet commitment |
| Vesting | Listed sends that create vesting accounts are refused. Scheduled unlocks and staking accounting follow SDK rules. Spendable tranches can be swept to recovery. | App tests for periodic, continuous, delayed and permanent vesting and sweeps on local chain A |
| Dualstaking | New delegation and redelegation are refused. Unbond and claim rewards are allowed with a configured fee payer. Unbond checks the withdraw address. | Rule and app tests |
| Pairing | Provider unstake is allowed with a configured fee payer and a safe withdraw address. Provider stake, move stake, relay payment and maintenance signed by a listed account are refused. | Tagged provider unstake with stake returned to the vault |
| Subscription and projects | Listed purchases and project changes are refused. The coin rule also refuses an automatic renewal charged to a listed creator, including a renewal initiated by an unlisted consumer. | Rule tests, app renewal test |
| IPRPC and other modules | Listed IPRPC funding is refused. Other listed messages are denied by default. Module rewards, slashing and ordinary module bookkeeping follow their existing rules. | Rule tests and a tagged IPRPC test with a funded spec and direct keeper debit rejection |

## Wiring

[`app/ante.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/ante.go) adds the lock before fee deduction. It inspects listed message signers, the fee payer and the fee granter. Signature verification and fee deduction remain SDK operations. Dispatch checks run again when authz, group or the ICA host invokes a message handler without an ante pass.

[`app/app.go`](https://github.com/alagiz/lava/blob/recovery-lock/app/app.go) installs the bank wrapper before handing the keeper to consumers. It guards `SendCoins`, `InputOutputCoins`, `SendCoinsFromAccountToModule`, `DelegateCoinsFromAccountToModule` and `DelegateCoins`. The SDK bank AppModule retains the concrete base keeper for its migration assertion. The primary router's bank messages pass through ante, and the dispatch router guards those same services when invoked by authz, group or ICA. Governance keeps the primary router and its authority check.

The app registers message services in both routers through `Tee`. Authz and group take the SDK's concrete `MsgServiceRouter`, so each gets the guarded router directly. The first staking hook resets a listed wallet's unsafe withdraw address before any distribution hook runs. The activation report reads existing account state. The app adds no store and requires no SDK fork changes.

## Builds, CI and release

The consensus job in [`.github/workflows/lava.yml`](https://github.com/alagiz/lava/blob/recovery-lock/.github/workflows/lava.yml) runs the ordinary app and module suites and a separate tagged run of the app and lock package. The tag enables test-only configuration injection. Local-chain builds embed separate test fixtures under that tag. Stage release settings in a separate checkout.

The publish workflow builds with `goreleaser/goreleaser-cross:v1.22` and [`.goreleaser.yaml`](https://github.com/alagiz/lava/blob/recovery-lock/.goreleaser.yaml). It runs the repository's tidy and generation hooks and builds `lavad` using CGO, `-trimpath`, stripped linker flags and `netgo,ledger`. Prepare a clean release checkout with the agreed bytes of both embedded files, commit those bytes for the build and pin the release tag and cross-build image digest. Compare binaries from two clean checkouts of that same commit and toolchain. Use the publish-disabled release path for the rehearsal. Record the resulting binary and file SHA-256 digests.

Smoke-test startup in an isolated home. A release binary with a placeholder in an address field, `test_values` true, a known test address, or missing `latest_vesting_end` must refuse to start. Verify the enabled configuration reports release mode with the agreed list digest, params digest, activation height and expiry. Only the enabled configuration applies the lock.

## Operations runbook

### Before the halt

Agree on the first locked height H and set each validator's `halt-height` to H minus one. Confirm the deployment release against the chain's applied and pending upgrades. Rebase onto the release mainnet runs before deployment if it changes. Read the listed accounts' vesting schedules from the deployment state and choose an expiry that meets both minimum bounds. Agree on the binary and both configuration SHA-256 digests. Stage them before restarting validators one at a time with the halt height set.

Prepare the adoption probe before the halt. A controlled listed account grants a configured fee payer permission to send a small amount to that listed account's registered recovery address. Use a grant with a spend limit, recipient allow-list and expiration beyond the activation height. Only the operator needs to control both accounts.

### Restart manually or through cosmovisor

At H minus one, Cosmos SDK v0.47 commits and then signals shutdown. Check the last committed height and wait for the process to exit. Verify the lock binary digest, clear `halt-height` to zero, start and compare the configuration log to the agreed values. With strictly more than two thirds of voting power running, the chain can commit H. During a coordinated halt with insufficient online voting power, a single missed validator cannot independently execute H.

For cosmovisor v1.7.1, rehearse `add-upgrade` at H minus one with the validators' actual RPC and service settings. Disable automatic downloads and enable restart after upgrade. Store an executable hook under the node's `cosmovisor` directory and set `COSMOVISOR_CUSTOM_PREUPGRADE` to its relative path. Have the hook clear `halt-height` on the node. Cosmovisor polls the daemon status command for the trigger height. The SDK halt can close RPC before the poll observes H minus one. If the watcher misses the trigger, verify the committed height and use the manual swap. Confirm the hook result, the `current` symlink, release configuration log and block progress before signing the adoption probe.

### Verify adoption and recover a stale node

Have the configured fee payer submit the prepared authz send as a `MsgExec`, using a positive fee. On a lock node it passes CheckTx and fails during delivery with the recovery lock code. Verify the listed and recovery balances remain unchanged and compare the next block's app hash and height on each validator. A node running the old binary executes the send and reports a wrong app hash at the next block. Before the probe, identical app hashes can occur on both binaries.

Stop a node that diverged at the probe. For a one-block divergence, the old binary's `lavad rollback` rolls back the committed probe block. Restart with the correct lock binary and `halt-height = 0`, let it replay that block and compare the next app hash. Preserve consensus signing state. If the recorded divergence spans more than one block, establish the node's committed application and blockstore heights before attempting recovery.

### Abort and expiry

Before H commits, a coordinated abort can restore the old binary and clear the halt on all validators. Check application and blockstore heights first, and preserve validator signing state. For cosmovisor, stop the service, restore its previous binary pointer, and remove the locally staged plan only after confirming its name and height. Once H commits, treat any removal or alteration of an active lock as a coordinated consensus upgrade.

At the first committed block with header time at or after expiry, the lock stops applying. CheckTx uses the latest committed header when it has one, so test a newly unlocked transaction after observing the expiry block commit. Extend the window by coordinating a binary with matching settings before the old expiry. Keep the original activation and historical checks intact for replay.

### Recover spendable and staked balances

Confirm the adoption probe first. Set each listed wallet's withdraw address to self or its registered recovery address in a separate transaction and verify it before undelegating or withdrawing. Withdraw available rewards, undelegate or use the applicable Lava unbonding message, and wait for the native completion time. Compare spendable balance and the approved destination before signing a sweep. Keep checking and sweeping through the last vesting tranche. Each transfer uses the listed signature and a configured fee payer signature. Set a positive fee in `ulava` that covers the submitting node's minimum gas price at the chosen gas limit.

## Tests

Package tests cover strict configuration, disabled wiring, the release window, message rules, the bank wrapper, staking hooks and nested dispatch. Tagged app tests use real SDK ante and signed transactions. They cover fee grants, authz, unbonding, rewards, four vesting account types, renewal, pre-activation app hashes and rejection of the same signed transaction before expiry followed by inclusion at expiry. The depth regression compares CheckTx, delivery and committed state for a seven-level unlisted transaction with the disabled build. Separate cases check the cap boundary and listed involvement through a signer, fee payer or fee granter.

The tagged IBC keeper tests exercise escrow and voucher burn guards, incoming credits, timeout refunds, packet forwarding and ICA host dispatch after IBC core proof verification. Use two isolated chains to rehearse proof-bearing transfers, packet forwarding, timeout refunds and error-acknowledgement refunds. The stock IBC Go v7 ICA controller requires an alphanumeric host account address at channel acknowledgement, which rejects the Lava `lava@` prefix. ICA host dispatch coverage uses the tagged keeper fixtures. Rehearse the release with an isolated mainnet-state replay before deployment.

## Limits

The lock does not reverse transfers executed before activation, prevent ordinary slashing, accelerate vesting or guarantee recovery if the configured fee payer accounts become unavailable. It restricts listed provider maintenance and relay payments as well as governance votes. Third-party delegations remain owned by their delegators.

Keep the lock and configuration in every binary that replays active blocks. A post-expiry binary that drops the rules may diverge when replaying earlier history. Any migration to another execution environment needs an explicit plan for still-locked balances. Rehearse the release against a copy of deployment chain state before deployment.
