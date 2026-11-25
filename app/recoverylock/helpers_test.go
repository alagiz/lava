package recoverylock

import (
	"crypto/sha256"
	"os"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

var testCodec = AddressCodec{Prefix: "lava@"}

// TestMain sets the Lava bech32 prefixes, which the messages' GetSigners
// read from the global SDK config.
func TestMain(m *testing.M) {
	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount("lava@", "lava@pub")
	cfg.SetBech32PrefixForValidator("lava@valoper", "lava@valoperpub")
	cfg.SetBech32PrefixForConsensusNode("lava@valcons", "lava@valconspub")
	os.Exit(m.Run())
}

func readTestData(t testing.TB) (listed, paramsJSON []byte) {
	t.Helper()
	listed, err := os.ReadFile("testdata/listed.txt")
	require.NoError(t, err)
	paramsJSON, err = os.ReadFile("testdata/params.json")
	require.NoError(t, err)
	return listed, paramsJSON
}

func seedAddr(seed string) sdk.AccAddress {
	h := sha256.Sum256([]byte(seed))
	return sdk.AccAddress((&secp256k1.PrivKey{Key: h[:]}).PubKey().Address())
}

func bech(t testing.TB, a []byte) string {
	t.Helper()
	s, err := testCodec.BytesToString(a)
	require.NoError(t, err)
	return s
}

// test accounts of testdata/
var (
	l0       = seedAddr("recoverylock-test-listed-0")
	l1       = seedAddr("recoverylock-test-listed-1")
	l2       = seedAddr("recoverylock-test-listed-2")
	recovery = seedAddr("recoverylock-test-recovery")
	unlisted = seedAddr("recoverylock-unlisted")
	payer0   = seedAddr("recoverylock-test-fee-payer-0")
	payer8   = seedAddr("recoverylock-test-fee-payer-8")
	attacker = sdk.AccAddress(make([]byte, 20))
)

func init() {
	for i := range attacker {
		attacker[i] = 0xa7
	}
}

type fakeDistr struct {
	withdraw map[string]sdk.AccAddress
	deleted  int
}

func (f *fakeDistr) GetDelegatorWithdrawAddr(_ sdk.Context, del sdk.AccAddress) sdk.AccAddress {
	if w, ok := f.withdraw[string(del)]; ok {
		return w
	}
	return del
}

func (f *fakeDistr) DeleteDelegatorWithdrawAddr(_ sdk.Context, del, _ sdk.AccAddress) {
	delete(f.withdraw, string(del))
	f.deleted++
}

// testLock builds the lock from testdata with activation height 20 and the
// testdata expiry.
func testLock(t testing.TB) (*Lock, *fakeDistr) {
	t.Helper()
	listed, paramsJSON := readTestData(t)
	cfg, _, err := parseConfig(listed, paramsJSON, testCodec, nil, true)
	require.NoError(t, err)
	distr := &fakeDistr{withdraw: map[string]sdk.AccAddress{}}
	return New(cfg, testCodec, distr, nil), distr
}
