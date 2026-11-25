//go:build !recoverylock_test

package recoverylock

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReleaseStartupRejectsTestConfig(t *testing.T) {
	previousList, previousManifest := listedFile, paramsFile
	t.Cleanup(func() { listedFile, paramsFile = previousList, previousManifest })

	listed, release := releaseFixture(t, 1)
	listedFile, paramsFile = listed, encodeParams(t, release)
	require.NotNil(t, MustConfig(testCodec, nil, nil))

	t.Run("test values flag", func(t *testing.T) {
		p := release
		p.TestValues = true
		listedFile, paramsFile = listed, encodeParams(t, p)
		require.PanicsWithValue(t, "recovery lock config: test values outside a recoverylock_test build", func() {
			MustConfig(testCodec, nil, nil)
		})
	})

	original := strings.Split(string(listed), "\n")[1]
	destination := release.RecoveryAddresses[original]
	listedFixture := bech(t, l0)
	recoveryFixture := bech(t, recovery)
	payerFixture := bech(t, payer0)
	tests := []struct {
		name   string
		list   []byte
		change func(*params)
		field  string
		addr   string
	}{
		{
			name: "listed wallet",
			list: []byte("# release fixture\n" + listedFixture + "\n"),
			change: func(p *params) {
				p.RecoveryAddresses = map[string]string{listedFixture: destination}
			},
			field: "list line 2",
			addr:  listedFixture,
		},
		{
			name: "recovery destination",
			list: listed,
			change: func(p *params) {
				p.RecoveryAddresses = map[string]string{original: recoveryFixture}
			},
			field: "recovery address for " + original,
			addr:  recoveryFixture,
		},
		{
			name: "fee payer",
			list: listed,
			change: func(p *params) {
				p.FeePayers = append([]string(nil), p.FeePayers...)
				p.FeePayers[0] = payerFixture
			},
			field: "fee payer 0",
			addr:  payerFixture,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := release
			tc.change(&p)
			p.ListSHA256 = fmt.Sprintf("%x", sha256.Sum256(tc.list))
			listedFile, paramsFile = tc.list, encodeParams(t, p)
			want := fmt.Sprintf("recovery lock config: %s %q is a known test address", tc.field, tc.addr)
			require.PanicsWithValue(t, want, func() {
				MustConfig(testCodec, nil, nil)
			})
		})
	}
}

func TestReleaseStartupRejectsManifestPlaceholders(t *testing.T) {
	manifest := readMainnetWalletManifest(t)
	previousList, previousParams := listedFile, paramsFile
	t.Cleanup(func() { listedFile, paramsFile = previousList, previousParams })

	listed, release := releaseFixture(t, 1)
	wallet := strings.Split(string(listed), "\n")[1]
	listedFile, paramsFile = listed, encodeParams(t, release)
	require.NotNil(t, MustConfig(testCodec, nil, nil))

	t.Run("listed wallet", func(t *testing.T) {
		p := release
		listedFile = []byte("# release fixture\n" + manifest.Wallets[1] + "\n")
		p.ListSHA256 = fmt.Sprintf("%x", sha256.Sum256(listedFile))
		paramsFile = encodeParams(t, p)
		requirePlaceholderPanic(t, "list line 2", manifest.Wallets[1])
	})

	t.Run("recovery address", func(t *testing.T) {
		p := release
		p.RecoveryAddresses = map[string]string{wallet: manifest.RecoveryAddress}
		listedFile, paramsFile = listed, encodeParams(t, p)
		requirePlaceholderPanic(t, "recovery address for "+wallet, manifest.RecoveryAddress)
	})

	t.Run("fee payer", func(t *testing.T) {
		p := release
		p.FeePayers = []string{manifest.FeePayerAddress}
		listedFile, paramsFile = listed, encodeParams(t, p)
		requirePlaceholderPanic(t, "fee payer 0", manifest.FeePayerAddress)
	})
}

func requirePlaceholderPanic(t *testing.T, field, placeholder string) {
	t.Helper()
	value := func() (value any) {
		defer func() { value = recover() }()
		MustConfig(testCodec, nil, nil)
		return nil
	}()
	require.NotNil(t, value, "release startup accepted a placeholder")
	require.Contains(t, fmt.Sprint(value), fmt.Sprintf("recovery lock config: %s %q:", field, placeholder))
}
