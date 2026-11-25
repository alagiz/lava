# Recovery lock for Lava

[LOCK-LAVA.md](https://github.com/alagiz/lava/blob/recovery-lock/LOCK-LAVA.md) describes the implementation, release configuration and validator runbook.

## Problem

The wallet owners and the attacker can both sign for the affected accounts. Liquid balances can be moved immediately, staked principal becomes liquid at unbonding maturity, and scheduled vesting creates further release points. Existing grants and module activity can act without a new signature from the wallet.

## Goal

Give the recovery operator a bounded window to preserve and recover balances. Each recovery transaction requires the listed wallet's signature and an approved fee payer's signature. Outgoing bank transfers from a listed wallet go to the registered recovery address.

## Deployment

The rules start for all listed wallets at height H and expire when the block header time reaches the configured expiry. Validators set `halt-height` to H minus one because the SDK commits the configured halt block before stopping. They swap binaries and clear the halt before committing H. The patch introduces no new store, migration or on-chain upgrade plan.

The adoption probe uses a controlled listed account and a previously issued authorization. During the window, the lock rejects the probe during execution and a stale binary executes it. Validators compare the subsequent block, confirm adoption and then begin recovery. Retain the historical lock rules in binaries that replay the recovery window.

## Configuration

The affected wallets, recovery address and fee payer will be provided separately once the Lava team is open to this kind of change. In the release checkout, replace the entire wallet array and both address fields in the [release manifest](https://github.com/alagiz/lava/blob/recovery-lock/app/recoverylock/mainnet-wallets.json). Count and hash the ordered wallet list from the repository root, then stage the embedded files and check the startup log using the [release configuration guide](https://github.com/alagiz/lava/blob/recovery-lock/LOCK-LAVA.md#configuration).

```sh
jq -er '.wallets[]' app/recoverylock/mainnet-wallets.json | wc -l
jq -er '.wallets[]' app/recoverylock/mainnet-wallets.json | sha256sum
```

The unmodified source build uses the disabled configuration. An enabled release refuses to start if any placeholder remains in its embedded wallet list, recovery addresses or fee payers.

## Enforcement

Ante requires a positive fee from a configured co-signer and an empty fee granter for listed recovery transactions. Allowed messages cover sends to recovery, undelegation, safe distribution operations, Lava provider unstake and dualstaking unbonding and reward claims. All other messages signed by a listed wallet are refused. The six-level authz depth limit applies when a listed signer, fee payer or fee granter is involved.

The bank wrapper checks listed-account debits, including staking, fee deductions, IBC escrow and voucher burns, and automatic subscription charges. Authz, group and ICA host use the guarded dispatch router. The first staking hook resets unsafe withdraw addresses to the listed wallet before distribution hooks run. Unbonding principal, IBC receipts and refunds can credit a listed account.

## Vesting and expiry

The deployment config requires expiry at least two unbonding periods plus seven days after the later of estimated activation and the latest listed vesting end. The first period allows filled unbonding entries to clear, the second allows the recovery undelegation to mature, and the seven days allow the operator to send the funds. Expiry can be at most 365 days after that minimum and at most 1096 days after estimated activation. The application logs observed vesting end times at H. The operator sweeps each tranche or unbonding after it becomes spendable. Permanent locks and ordinary slashing remain subject to the SDK rules.

## Verification

The app tests exercise signed recovery transactions, indirect dispatch, automatic bank debits, vesting and expiry. The transfer and ICA host keeper tests exercise wired IBC application logic after proof verification. Use local relaying to exercise transfers, forwarding and refunds. The standard IBC Go v7 ICA controller rejects the Lava account prefix during channel acknowledgement. Validate the release against an isolated copy of mainnet state before deployment.
