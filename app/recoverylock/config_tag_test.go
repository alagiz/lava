//go:build recoverylock_test

package recoverylock

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUseTestConfig(t *testing.T) {
	listed, paramsJSON := readTestData(t)
	restore := UseTestConfig(listed, paramsJSON)
	cfg := MustConfig(testCodec, nil, nil)
	require.NotNil(t, cfg)
	require.Len(t, cfg.recoveries, 3)
	restore()
	require.Nil(t, MustConfig(testCodec, nil, nil))
	bad := bytes.Replace(paramsJSON, []byte(`"list_count": 3`), []byte(`"list_count": 4`), 1)
	require.NotEqual(t, paramsJSON, bad)
	t.Cleanup(UseTestConfig(listed, bad))
	require.Panics(t, func() { MustConfig(testCodec, nil, nil) })
}
