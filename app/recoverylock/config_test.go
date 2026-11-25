package recoverylock

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedConfigDisabled(t *testing.T) {
	for _, test := range []bool{false, true} {
		cfg, p, err := parseConfig(listedFile, paramsFile, testCodec, nil, test)
		require.NoError(t, err)
		require.Nil(t, cfg)
		require.False(t, p.Enabled)
	}
	require.Nil(t, MustConfig(testCodec, nil, nil))
	require.Nil(t, New(nil, testCodec, nil, nil))
}

func TestDisabledConfigCarriesNoData(t *testing.T) {
	listed, paramsJSON := readTestData(t)
	disabled := bytes.Replace(paramsJSON, []byte(`"enabled": true`), []byte(`"enabled": false`), 1)
	require.NotEqual(t, paramsJSON, disabled)
	_, _, err := parseConfig(listedFile, disabled, testCodec, nil, true)
	require.ErrorContains(t, err, "sets fields")
	_, _, err = parseConfig(listed, paramsFile, testCodec, nil, true)
	require.ErrorContains(t, err, "has entries")
	_, _, err = parseConfig(listedFile, []byte(`{"enabled": false, "list_count": 0, "fee_payers": []}`), testCodec, nil, true)
	require.ErrorContains(t, err, "sets fields")
	_, _, err = parseConfig(listedFile, []byte(`{"enabled": false, "latest_vesting_end": 0}`), testCodec, nil, true)
	require.ErrorContains(t, err, "sets fields")
}

func TestTestDataConfig(t *testing.T) {
	listed, paramsJSON := readTestData(t)
	cfg, p, err := parseConfig(listed, paramsJSON, testCodec, nil, true)
	require.NoError(t, err)
	require.True(t, p.Enabled)
	require.True(t, p.TestValues)
	require.Len(t, cfg.recoveries, 3)
	require.Len(t, cfg.feePayers, 8)
	require.Len(t, cfg.listed, 3)
	for _, w := range []([]byte){l0, l1, l2} {
		require.True(t, cfg.isListed(w))
		require.True(t, cfg.isRecovery(w, recovery))
	}
	require.True(t, cfg.isFeePayer(payer0))
	require.False(t, cfg.isFeePayer(payer8))
	for wallet, destination := range cfg.recoveries {
		require.True(t, knownTestAddresses()[wallet])
		require.True(t, knownTestAddresses()[string(destination)])
	}
	// release rules refuse the test values
	_, _, err = parseConfig(listed, paramsJSON, testCodec, nil, false)
	require.ErrorContains(t, err, "test values")
}

// releaseFixture returns a list of n generated (non-test) wallets and release
// params that pass every release rule: activation 7000000 about 2026-12-15,
// 12.5 s blocks from a reference block, 21 day unbonding, latest vesting end
// 2028-05-11T15:00:00Z and expiry 2028-06-11T15:00:00Z.
func releaseFixture(t testing.TB, n int) ([]byte, params) {
	t.Helper()
	encode := func(prefix byte, i int) string {
		b := make([]byte, 20)
		b[0] = prefix
		b[16], b[17], b[18], b[19] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
		return bech(t, b)
	}
	var list strings.Builder
	list.WriteString("# release fixture\n")
	recoveries := map[string]string{}
	for i := 0; i < n; i++ {
		w := encode(1, i)
		list.WriteString(w + "\n")
		recoveries[w] = encode(2, i%7)
	}
	payers := make([]string, 8)
	for i := range payers {
		payers[i] = encode(3, i)
	}
	sum := sha256.Sum256([]byte(list.String()))
	vestingEnd := int64(1841670000) // 2028-05-11T15:00:00Z
	refTime := int64(1795460400)    // 2026-11-23T19:00:00Z
	refHeight := int64(6323700)
	activation := int64(7000000)
	estimate := refTime + (activation-refHeight)*125/10
	p := params{
		Enabled:                true,
		RecoveryAddresses:      recoveries,
		FeePayers:              payers,
		ActivationHeight:       activation,
		ExpiryTime:             vestingEnd + 49*86400 + 1,
		ActivationTimeEstimate: estimate,
		UnbondingSeconds:       1814400,
		EstimateRefHeight:      refHeight,
		EstimateRefTime:        refTime,
		LatestVestingEnd:       &vestingEnd,
		ListSHA256:             hex.EncodeToString(sum[:]),
		ListCount:              n,
	}
	return []byte(list.String()), p
}

func encodeParams(t testing.TB, p params) []byte {
	t.Helper()
	b, err := json.Marshal(p)
	require.NoError(t, err)
	return b
}

func TestReleaseFixtureAccepted(t *testing.T) {
	listed, p := releaseFixture(t, 50)
	cfg, _, err := parseConfig(listed, encodeParams(t, p), testCodec, nil, false)
	require.NoError(t, err)
	require.Len(t, cfg.recoveries, 50)
}

func TestReleaseRules(t *testing.T) {
	day := int64(86400)
	cases := []struct {
		name   string
		change func(*params)
		err    string
	}{
		{"test values", func(p *params) { p.TestValues = true }, "test values"},
		{"no fee payers", func(p *params) { p.FeePayers = nil }, "need 1 to 16 fee payers"},
		{"no estimate", func(p *params) { p.ActivationTimeEstimate = 0 }, "activation_time_estimate is required"},
		{"short unbonding", func(p *params) { p.UnbondingSeconds = 1814399 }, "below the mainnet unbonding time"},
		{"long unbonding", func(p *params) { p.UnbondingSeconds = 366 * day }, "not plausible"},
		{"no reference height", func(p *params) { p.EstimateRefHeight = 0 }, "estimate_ref_height and estimate_ref_time are required"},
		{"no reference time", func(p *params) { p.EstimateRefTime = 0 }, "estimate_ref_height and estimate_ref_time are required"},
		{"reference above activation", func(p *params) { p.EstimateRefHeight = p.ActivationHeight }, "must be above estimate_ref_height"},
		{"estimate before reference", func(p *params) { p.ActivationTimeEstimate = p.EstimateRefTime }, "later than estimate_ref_time"},
		{"blocks too fast", func(p *params) {
			p.ActivationTimeEstimate = p.EstimateRefTime + (p.ActivationHeight-p.EstimateRefHeight)*4
		}, "implied block time"},
		{"blocks too slow", func(p *params) {
			p.ActivationTimeEstimate = p.EstimateRefTime + (p.ActivationHeight-p.EstimateRefHeight)*31
		}, "implied block time"},
		{"vesting end missing", func(p *params) { p.LatestVestingEnd = nil }, "latest_vesting_end is required"},
		{"vesting end negative", func(p *params) { v := int64(-1); p.LatestVestingEnd = &v }, "must not be negative"},
		{"vesting end too late", func(p *params) {
			v := p.ActivationTimeEstimate + MaxReleaseWindowSeconds - 49*day + 1
			p.LatestVestingEnd = &v
			p.ExpiryTime = v + 49*day
		}, "latest_vesting_end leaves insufficient time"},
		{"expiry at old 30-day vesting bound", func(p *params) {
			p.ExpiryTime = *p.LatestVestingEnd + 30*day
		}, "two unbonding periods"},
		{"expiry one second below vesting bound", func(p *params) {
			p.ExpiryTime = *p.LatestVestingEnd + 49*day - 1
		}, "two unbonding periods"},
		{"expiry too early when vesting ends before activation", func(p *params) {
			v := p.ActivationTimeEstimate - day
			p.LatestVestingEnd = &v
			p.ExpiryTime = v + 49*day
		}, "two unbonding periods"},
		{"expiry before two unbonding periods", func(p *params) {
			v := int64(0)
			p.LatestVestingEnd = &v
			p.ExpiryTime = p.ActivationTimeEstimate + 2*p.UnbondingSeconds + ExpiryMarginSeconds - 1
		}, "two unbonding periods"},
		{"expiry too late after vesting end", func(p *params) { p.ExpiryTime = *p.LatestVestingEnd + 49*day + BaseReleaseWindowSeconds + 1 }, "at most one year after"},
		{"expiry too late without vesting", func(p *params) {
			v := int64(0)
			p.LatestVestingEnd = &v
			p.ExpiryTime = p.ActivationTimeEstimate + 49*day + BaseReleaseWindowSeconds + 1
		}, "at most one year after"},
		{"expiry beyond absolute cap", func(p *params) {
			v := p.ActivationTimeEstimate + MaxReleaseWindowSeconds - 49*day
			p.LatestVestingEnd = &v
			p.ExpiryTime = p.ActivationTimeEstimate + MaxReleaseWindowSeconds + 1
		}, "at most 1096 days"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			listed, p := releaseFixture(t, 5)
			c.change(&p)
			_, _, err := parseConfig(listed, encodeParams(t, p), testCodec, nil, false)
			require.ErrorContains(t, err, c.err)
		})
	}
	// boundaries that pass
	ok := []func(*params){
		func(p *params) { p.ExpiryTime = *p.LatestVestingEnd + 49*day },
		func(p *params) { p.ExpiryTime = *p.LatestVestingEnd + 49*day + BaseReleaseWindowSeconds },
		func(p *params) {
			v := int64(0)
			p.LatestVestingEnd = &v
			p.UnbondingSeconds = 365 * day
			p.ExpiryTime = p.ActivationTimeEstimate + 737*day
		},
		func(p *params) {
			v := int64(0)
			p.LatestVestingEnd = &v
			p.ExpiryTime = p.ActivationTimeEstimate + 2*p.UnbondingSeconds + ExpiryMarginSeconds
		},
		func(p *params) {
			v := p.ActivationTimeEstimate + MaxReleaseWindowSeconds - 49*day
			p.LatestVestingEnd = &v
			p.ExpiryTime = p.ActivationTimeEstimate + MaxReleaseWindowSeconds
		},
	}
	for i, change := range ok {
		listed, p := releaseFixture(t, 5)
		change(&p)
		_, _, err := parseConfig(listed, encodeParams(t, p), testCodec, nil, false)
		require.NoError(t, err, "boundary case %d", i)
	}
}

func TestConfigValidation(t *testing.T) {
	moduleAddr := bech(t, authtypes.NewModuleAddress("distribution"))
	blocked := map[string]bool{moduleAddr: true}
	cases := []struct {
		name   string
		change func(listed *string, p *params)
		err    string
	}{
		{"hash mismatch", func(l *string, p *params) { p.ListSHA256 = strings.Repeat("0", 64) }, "does not match"},
		{"count mismatch", func(l *string, p *params) { p.ListCount++ }, "expected a nonempty list"},
		{"duplicate", func(l *string, p *params) {
			first := strings.Split(*l, "\n")[1]
			*l += first + "\n"
			p.ListCount++
		}, "duplicate listed wallet"},
		{"bad address", func(l *string, p *params) { *l += "lava@1notanaddress\n"; p.ListCount++ }, "list line"},
		{"wrong prefix", func(l *string, p *params) {
			*l += "cosmos1p8v4sd70qvvg737wthgeuafc7hh20uf5ms8tes\n"
			p.ListCount++
		}, "list line"},
		{"module account listed", func(l *string, p *params) { *l += moduleAddr + "\n"; p.ListCount++ }, "module account"},
		{"missing recovery", func(l *string, p *params) {
			for k := range p.RecoveryAddresses {
				delete(p.RecoveryAddresses, k)
				p.RecoveryAddresses[bech(t, payer8)] = bech(t, recovery)
				break
			}
		}, "recovery address for"},
		{"recovery is listed", func(l *string, p *params) {
			first := strings.Split(*l, "\n")[1]
			for k := range p.RecoveryAddresses {
				if k != first {
					p.RecoveryAddresses[k] = first
					break
				}
			}
		}, "cannot be a listed wallet"},
		{"recovery is module account", func(l *string, p *params) {
			for k := range p.RecoveryAddresses {
				p.RecoveryAddresses[k] = moduleAddr
				break
			}
		}, "module account"},
		{"fee payer listed", func(l *string, p *params) { p.FeePayers[0] = strings.Split(*l, "\n")[1] }, "fee payer 0 overlaps"},
		{"fee payer twice", func(l *string, p *params) { p.FeePayers[2] = p.FeePayers[3] }, "fee payer 3 overlaps"},
		{"too many fee payers", func(l *string, p *params) {
			for i := 0; i < 9; i++ {
				p.FeePayers = append(p.FeePayers, bech(t, seedAddr(fmt.Sprintf("extra-payer-%d", i))))
			}
		}, "need 1 to 16 fee payers"},
		{"zero activation", func(l *string, p *params) { p.ActivationHeight = 0 }, "must be positive"},
		{"known test address", func(l *string, p *params) { p.FeePayers[0] = bech(t, payer0) }, "known test address"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			listed, p := releaseFixture(t, 5)
			s := string(listed)
			c.change(&s, &p)
			if !strings.Contains(c.name, "hash") {
				sum := sha256.Sum256([]byte(s))
				p.ListSHA256 = hex.EncodeToString(sum[:])
			}
			_, _, err := parseConfig([]byte(s), encodeParams(t, p), testCodec, blocked, false)
			require.ErrorContains(t, err, c.err)
		})
	}
}

func TestReleaseRejectsAppFixtureAddresses(t *testing.T) {
	seeds := []string{"app-test-attacker", "app-test-control"}
	for i := 0; i < 5; i++ {
		seeds = append(seeds, fmt.Sprintf("app-test-listed-%d", i))
	}
	for _, seed := range seeds {
		t.Run(seed, func(t *testing.T) {
			listed, p := releaseFixture(t, 5)
			p.FeePayers[0] = bech(t, seedAddr(seed))
			_, _, err := parseConfig(listed, encodeParams(t, p), testCodec, nil, false)
			require.ErrorContains(t, err, "known test address")
		})
	}
}

func TestStrictParams(t *testing.T) {
	listed, p := releaseFixture(t, 3)
	good := encodeParams(t, p)
	_, _, err := parseConfig(listed, good, testCodec, nil, false)
	require.NoError(t, err)
	for name, bad := range map[string]string{
		"unknown key":   strings.Replace(string(good), `"enabled":true`, `"enabled":true,"extra":1`, 1),
		"wrong case":    strings.Replace(string(good), `"enabled":true`, `"Enabled":true`, 1),
		"duplicate key": strings.Replace(string(good), `"enabled":true`, `"enabled":true,"enabled":true`, 1),
		"trailing data": string(good) + "{}",
		"wrong type":    strings.Replace(string(good), `"list_count":3`, `"list_count":"3"`, 1),
		"not an object": `[1]`,
	} {
		require.NotEqual(t, string(good), bad, name)
		_, _, err := parseConfig(listed, []byte(bad), testCodec, nil, false)
		require.Error(t, err, name)
	}
}

func TestMustConfigPanicsOnBadConfig(t *testing.T) {
	// The embedded configuration is valid and disabled.
	require.NotPanics(t, func() { MustConfig(testCodec, nil, nil) })
	listed, _ := readTestData(t)
	_, _, err := parseConfig(listed, []byte(`{"enabled": true}`), testCodec, nil, true)
	require.Error(t, err)
}

// BenchmarkParseConfig10k measures startup validation of a 10000 wallet list.
func BenchmarkParseConfig10k(b *testing.B) {
	listed, p := releaseFixture(b, 10000)
	raw := encodeParams(b, p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg, _, err := parseConfig(listed, raw, testCodec, nil, false)
		if err != nil || len(cfg.recoveries) != 10000 {
			b.Fatal(err)
		}
	}
}
