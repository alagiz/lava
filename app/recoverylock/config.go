// Package recoverylock enforces a height and time bounded policy for listed
// wallets. The configuration is embedded (params.json and listed.txt) and
// validated at startup. The committed configuration is disabled: the app then
// wires none of the lock components and runs exactly like the release it is
// based on. A release with a real list sets "enabled": true.
package recoverylock

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/types/bech32"
)

//go:embed listed.txt
var listedFile []byte

//go:embed params.json
var paramsFile []byte

// ExpiryMarginSeconds leaves time to send recovered funds after two
// unbonding periods counted from the later of activation and the latest
// vesting end. Filled unbonding entries can delay a new undelegation by one
// period, and the new undelegation takes another period to complete.
const ExpiryMarginSeconds = 7 * 24 * 3600

// BaseReleaseWindowSeconds caps expiry at one year after the minimum expiry.
const BaseReleaseWindowSeconds = 365 * 24 * 3600

// MaxReleaseWindowSeconds is the absolute cap on expiry_time in release
// builds: expiry_time <= activation_time_estimate + 3 years (1096 days), so a
// mistyped expiry or vesting end cannot keep the listed wallets locked for
// longer than that without another binary.
const MaxReleaseWindowSeconds = 1096 * 24 * 3600

// The release estimate band is a sanity check for lava-mainnet-1.
// Use measured headers for releases.
const (
	MinMillisPerBlock          = 5000
	MaxMillisPerBlock          = 30000
	MinReleaseUnbondingSeconds = 21 * 24 * 3600
)

// AddressCodec converts between bech32 strings with one prefix and address
// bytes.
type AddressCodec struct{ Prefix string }

// StringToBytes decodes a bech32 address with the codec prefix.
func (c AddressCodec) StringToBytes(s string) ([]byte, error) {
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("empty address")
	}
	hrp, b, err := bech32.DecodeAndConvert(s)
	if err != nil {
		return nil, err
	}
	if hrp != c.Prefix {
		return nil, fmt.Errorf("address prefix %q, want %q", hrp, c.Prefix)
	}
	return b, nil
}

// BytesToString encodes address bytes as bech32 with the codec prefix.
func (c AddressCodec) BytesToString(b []byte) (string, error) {
	return bech32.ConvertAndEncode(c.Prefix, b)
}

type Config struct {
	recoveries       map[string][]byte
	feePayers        map[string]struct{}
	activationHeight int64
	expiryTime       int64
	// listed keeps the listed wallets in list order for the activation
	// report.
	listed [][]byte
}

func (c *Config) isListed(addr []byte) bool {
	_, ok := c.recoveries[string(addr)]
	return ok
}

func (c *Config) isRecovery(wallet, destination []byte) bool {
	recovery, ok := c.recoveries[string(wallet)]
	return ok && bytes.Equal(recovery, destination)
}

func (c *Config) isFeePayer(addr []byte) bool {
	_, ok := c.feePayers[string(addr)]
	return ok
}

// The seeded local-chain keys are public and must never enter a release.
func knownTestAddresses() map[string]bool {
	seeds := []string{
		"recoverylock-test-recovery", "recoverylock-unlisted",
		"app-test-attacker", "app-test-control",
	}
	for i := 0; i < 5; i++ {
		seeds = append(seeds, fmt.Sprintf("app-test-listed-%d", i))
	}
	for i := 0; i < 3; i++ {
		seeds = append(seeds, fmt.Sprintf("recoverylock-test-listed-%d", i))
	}
	for i := 0; i < 16; i++ {
		seeds = append(seeds, fmt.Sprintf("recoverylock-test-fee-payer-%d", i))
	}
	out := make(map[string]bool, len(seeds))
	for _, seed := range seeds {
		h := sha256.Sum256([]byte(seed))
		out[string((&secp256k1.PrivKey{Key: h[:]}).PubKey().Address())] = true
	}
	return out
}

type params struct {
	// Enabled false is the committed state: no list, no other field set, and
	// the lock is not wired into the app.
	Enabled           bool              `json:"enabled"`
	RecoveryAddresses map[string]string `json:"recovery_addresses"`
	FeePayers         []string          `json:"fee_payers"`
	ActivationHeight  int64             `json:"activation_height"`
	ExpiryTime        int64             `json:"expiry_time"`
	// ActivationTimeEstimate is the expected block time (unix seconds) of the
	// activation height; UnbondingSeconds is the chain's live staking
	// unbonding_time. Release builds require
	// expiry_time >= max(activation_time_estimate, latest_vesting_end) +
	// 2 x unbonding_seconds + 7 days
	// (see ExpiryMarginSeconds).
	//
	// EstimateRefHeight and EstimateRefTime are a real mainnet block height
	// and its block time (unix seconds) taken when the config is built.
	// Release builds require activation_height > estimate_ref_height and the
	// implied block time (activation_time_estimate - estimate_ref_time) /
	// (activation_height - estimate_ref_height) within [MinMillisPerBlock,
	// MaxMillisPerBlock], which cross-checks the activation height against
	// the time estimate.
	//
	// Estimate method (at release time): take the latest block (height h0,
	// time t0; these are estimate_ref_height and estimate_ref_time) and the
	// block 10000 heights earlier (time t1) from a node; average block time
	// b = (t0 - t1) / 10000; estimate = t0 + (H - h0) * b rounded up to the
	// hour, where H is the activation height. Use the later of this and the
	// planned halt time. The 7 day margin absorbs block time drift and a slow
	// restart at the halt.
	ActivationTimeEstimate int64 `json:"activation_time_estimate"`
	UnbondingSeconds       int64 `json:"unbonding_seconds"`
	EstimateRefHeight      int64 `json:"estimate_ref_height"`
	EstimateRefTime        int64 `json:"estimate_ref_time"`
	// LatestVestingEnd is the latest end_time (unix seconds) of any vesting
	// account in the list, read from chain state when the list is built (0
	// when no listed wallet is a vesting account). It must be present in
	// release builds and is used to calculate the minimum expiry.
	// The node logs the value it finds in state at the activation height.
	LatestVestingEnd *int64 `json:"latest_vesting_end"`
	ListSHA256       string `json:"list_sha256"`
	ListCount        int    `json:"list_count"`
	TestValues       bool   `json:"test_values"`
}

// decodeParams checks case-sensitive field names, duplicate keys, value
// types and trailing data before decoding an embedded manifest.
func decodeParams[T any](b []byte, p *T) error {
	v, err := strictJSON(b)
	if err != nil {
		return err
	}
	top, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("params must be a JSON object")
	}
	fields := reflect.TypeOf(*p)
	keys := make(map[string]bool, fields.NumField())
	for i := 0; i < fields.NumField(); i++ {
		keys[strings.Split(fields.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	for k := range top {
		if !keys[k] {
			return fmt.Errorf("unknown key %q", k)
		}
	}
	return json.Unmarshal(b, p)
}

func parseParams(b []byte) (params, error) {
	var p params
	err := decodeParams(b, &p)
	return p, err
}

func source() (listed, paramsJSON []byte, test bool) {
	if listed, paramsJSON, ok := testConfigOverride(); ok {
		return listed, paramsJSON, true
	}
	return listedFile, paramsFile, testBuild
}

// MustConfig validates the embedded configuration and logs its release
// identifiers. It returns nil when the configuration is disabled; the app
// then wires no lock component. It panics on an invalid configuration, so a
// node with a bad or incomplete list does not start. The blocked map must
// include every module account as a key (bech32 strings with the account
// prefix).
func MustConfig(ac AddressCodec, blocked map[string]bool, logger log.Logger) *Config {
	listed, paramsJSON, test := source()
	cfg, p, err := parseConfig(listed, paramsJSON, ac, blocked, test)
	if err != nil {
		panic("recovery lock config: " + err.Error())
	}
	mode := "release"
	if test {
		mode = "test"
	}
	paramsSum := fmt.Sprintf("%x", sha256.Sum256(paramsJSON))
	if cfg == nil {
		if logger != nil {
			logger.Info("recovery lock disabled", "params_sha256", paramsSum)
		}
		return nil
	}
	if logger != nil {
		expiry := cfg.expiryTime
		latestVestingEnd := int64(0)
		if p.LatestVestingEnd != nil {
			latestVestingEnd = *p.LatestVestingEnd
		}
		logger.Info("recovery lock config",
			"mode", mode,
			"activation_height", cfg.activationHeight,
			"expiry_time", expiry,
			"expiry_utc", time.Unix(expiry, 0).UTC().Format(time.RFC3339),
			"latest_vesting_end", latestVestingEnd,
			"recovery_count", len(cfg.recoveries),
			"params_sha256", paramsSum,
			"fee_payers", len(cfg.feePayers),
			"list_count", p.ListCount,
			"list_sha256", strings.ToLower(p.ListSHA256),
		)
	}
	return cfg
}

// checkEstimate cross-checks the activation height against the activation
// time estimate (release builds).
func checkEstimate(p params) error {
	if p.EstimateRefHeight <= 0 || p.EstimateRefTime <= 0 {
		return fmt.Errorf("estimate_ref_height and estimate_ref_time are required")
	}
	if p.ActivationHeight <= p.EstimateRefHeight {
		return fmt.Errorf("activation_height %d must be above estimate_ref_height %d", p.ActivationHeight, p.EstimateRefHeight)
	}
	if p.ActivationTimeEstimate <= p.EstimateRefTime {
		return fmt.Errorf("activation_time_estimate must be later than estimate_ref_time")
	}
	dh := p.ActivationHeight - p.EstimateRefHeight
	dt := p.ActivationTimeEstimate - p.EstimateRefTime
	// bounds keep the products below 2^63
	const limit = int64(1) << 40
	if dt >= limit || dh >= limit {
		return fmt.Errorf("activation_time_estimate %d is not plausible after estimate_ref_time %d", p.ActivationTimeEstimate, p.EstimateRefTime)
	}
	if dt*1000 < MinMillisPerBlock*dh || dt*1000 > MaxMillisPerBlock*dh {
		return fmt.Errorf("implied block time %d ms ((activation_time_estimate - estimate_ref_time) / (activation_height - estimate_ref_height)) is outside %d to %d ms",
			dt*1000/dh, MinMillisPerBlock, MaxMillisPerBlock)
	}
	return nil
}

// checkReleaseExpiry applies the release bounds on expiry_time.
func checkReleaseExpiry(p params) error {
	if p.LatestVestingEnd == nil {
		return fmt.Errorf("latest_vesting_end is required (0 when no listed wallet is a vesting account)")
	}
	vestingEnd := *p.LatestVestingEnd
	if vestingEnd < 0 {
		return fmt.Errorf("latest_vesting_end must not be negative")
	}
	activation := p.ActivationTimeEstimate
	start := max(activation, vestingEnd)
	minimumWindow := 2*p.UnbondingSeconds + ExpiryMarginSeconds
	if start-activation > MaxReleaseWindowSeconds-minimumWindow {
		return fmt.Errorf("latest_vesting_end leaves insufficient time for two unbonding periods and seven days within the 1096-day cap")
	}
	if p.ExpiryTime-start < minimumWindow {
		return fmt.Errorf("expiry_time must allow two unbonding periods and seven days after the later of the activation estimate and latest_vesting_end")
	}
	if p.ExpiryTime-start > minimumWindow+BaseReleaseWindowSeconds || p.ExpiryTime-activation > MaxReleaseWindowSeconds {
		return fmt.Errorf("expiry_time must be at most one year after the minimum expiry, and at most 1096 days after the activation estimate")
	}
	return nil
}

// parseConfig returns a nil Config without error for a valid disabled
// configuration.
func parseConfig(listed, paramsJSON []byte, ac AddressCodec, blocked map[string]bool, test bool) (*Config, params, error) {
	p, err := parseParams(paramsJSON)
	if err != nil {
		return nil, p, fmt.Errorf("params: %w", err)
	}
	if !p.Enabled {
		return nil, p, checkDisabled(listed, p)
	}
	cfg, err := build(listed, p, ac, blocked, test)
	return cfg, p, err
}

// checkDisabled refuses a disabled configuration that carries data, so a real
// list with "enabled" left false fails at startup instead of running unlocked.
func checkDisabled(listed []byte, p params) error {
	if !reflect.ValueOf(p).IsZero() {
		return fmt.Errorf(`params.json sets fields while "enabled" is false`)
	}
	for _, line := range strings.Split(string(listed), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return fmt.Errorf(`listed.txt has entries while "enabled" is false`)
		}
	}
	return nil
}

func build(listed []byte, p params, ac AddressCodec, blocked map[string]bool, test bool) (*Config, error) {
	if p.ActivationHeight <= 0 || p.ExpiryTime <= 0 {
		return nil, fmt.Errorf("activation height and expiry time must be positive")
	}
	if len(p.FeePayers) == 0 || len(p.FeePayers) > 16 {
		return nil, fmt.Errorf("need 1 to 16 fee payers")
	}

	if !test {
		if p.TestValues {
			return nil, fmt.Errorf("test values outside a recoverylock_test build")
		}
		if p.ActivationTimeEstimate <= 0 {
			return nil, fmt.Errorf("activation_time_estimate is required")
		}
		if p.UnbondingSeconds < MinReleaseUnbondingSeconds {
			return nil, fmt.Errorf("unbonding_seconds %d is below the mainnet unbonding time %d", p.UnbondingSeconds, MinReleaseUnbondingSeconds)
		}
		if p.UnbondingSeconds > 365*24*3600 {
			return nil, fmt.Errorf("unbonding_seconds %d is not plausible", p.UnbondingSeconds)
		}
		if err := checkEstimate(p); err != nil {
			return nil, err
		}
		if err := checkReleaseExpiry(p); err != nil {
			return nil, err
		}
	}
	if err := checkListHash("listed.txt", listed, p.ListSHA256); err != nil {
		return nil, err
	}
	decode := walletDecoder(ac, blocked, test)
	cfg := &Config{
		recoveries:       make(map[string][]byte),
		feePayers:        make(map[string]struct{}, len(p.FeePayers)),
		activationHeight: p.ActivationHeight,
		expiryTime:       p.ExpiryTime,
	}
	lines := strings.Split(string(listed), "\n")
	wallets := make([][]byte, 0, len(lines))
	listedKeys := make(map[string]struct{}, len(lines))
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		wallet, err := decode(fmt.Sprintf("list line %d", i+1), line)
		if err != nil {
			return nil, err
		}
		if _, duplicate := listedKeys[string(wallet)]; duplicate {
			return nil, fmt.Errorf("duplicate listed wallet on line %d", i+1)
		}
		listedKeys[string(wallet)] = struct{}{}
		wallets = append(wallets, wallet)
	}
	if len(wallets) == 0 || len(wallets) != p.ListCount {
		return nil, fmt.Errorf("listed.txt has %d wallets, expected a nonempty list of %d", len(wallets), p.ListCount)
	}
	if len(p.RecoveryAddresses) != len(wallets) {
		return nil, fmt.Errorf("recovery_addresses must have one entry per listed wallet")
	}
	for _, wallet := range wallets {
		canonical, err := ac.BytesToString(wallet)
		if err != nil {
			return nil, err
		}
		recovery, err := decode("recovery address for "+canonical, p.RecoveryAddresses[canonical])
		if err != nil {
			return nil, err
		}
		if _, listed := listedKeys[string(recovery)]; listed {
			return nil, fmt.Errorf("a recovery address cannot be a listed wallet")
		}
		cfg.recoveries[string(wallet)] = recovery
	}
	cfg.listed = wallets
	for i, value := range p.FeePayers {
		payer, err := decode(fmt.Sprintf("fee payer %d", i), value)
		if err != nil {
			return nil, err
		}
		key := string(payer)
		if cfg.isListed(payer) || cfg.isFeePayer(payer) {
			return nil, fmt.Errorf("fee payer %d overlaps a listed wallet or another fee payer", i)
		}
		cfg.feePayers[key] = struct{}{}
	}
	return cfg, nil
}

func checkListHash(name string, data []byte, expected string) error {
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, expected) {
		return fmt.Errorf("%s sha256 %s does not match params %s", name, got, expected)
	}
	return nil
}

func walletDecoder(ac AddressCodec, blocked map[string]bool, test bool) func(string, string) ([]byte, error) {
	known := knownTestAddresses()
	return func(what, s string) ([]byte, error) {
		b, err := ac.StringToBytes(s)
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", what, s, err)
		}
		if len(b) != 20 {
			return nil, fmt.Errorf("%s %q has %d bytes, want 20", what, s, len(b))
		}
		if !test && known[string(b)] {
			return nil, fmt.Errorf("%s %q is a known test address", what, s)
		}
		canon, err := ac.BytesToString(b)
		if err != nil {
			return nil, err
		}
		if _, isBlocked := blocked[canon]; isBlocked {
			return nil, fmt.Errorf("%s %q is a module account or blocked address", what, s)
		}
		return b, nil
	}
}
