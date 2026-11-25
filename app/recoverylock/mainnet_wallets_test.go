package recoverylock

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	mainnetWalletCount         = 2
	mainnetWalletSHA256        = "980f32f93af160b6f7e0db12bd1b0794115352ec53c95fe88e258d20354366f4"
	mainnetRecoveryPlaceholder = "RECOVERY_ADDRESS"
	mainnetWalletPlaceholder   = "AFFECTED_WALLET_ADDRESS"
	mainnetFeePayerPlaceholder = "FEE_PAYER_ADDRESS"
)

type mainnetWalletManifest struct {
	ChainID         string   `json:"chain_id"`
	RecoveryAddress string   `json:"recovery_address"`
	FeePayerAddress string   `json:"fee_payer_address"`
	Wallets         []string `json:"wallets"`
}

func readMainnetWalletManifest(t *testing.T) mainnetWalletManifest {
	t.Helper()
	data, err := os.ReadFile("mainnet-wallets.json")
	require.NoError(t, err)
	var manifest mainnetWalletManifest
	require.NoError(t, decodeParams(data, &manifest))
	return manifest
}

func TestMainnetWalletManifest(t *testing.T) {
	manifest := readMainnetWalletManifest(t)
	require.Equal(t, "lava-mainnet-1", manifest.ChainID)
	require.Equal(t, mainnetRecoveryPlaceholder, manifest.RecoveryAddress)
	require.Equal(t, mainnetFeePayerPlaceholder, manifest.FeePayerAddress)
	require.Len(t, manifest.Wallets, mainnetWalletCount)
	require.Equal(t, mainnetWalletPlaceholder, manifest.Wallets[1])
	require.Equal(t, mainnetWalletSHA256, fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(manifest.Wallets, "\n")+"\n"))))
}
