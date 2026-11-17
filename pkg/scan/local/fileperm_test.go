package local

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_setuidMisconfigurations(t *testing.T) {
	layer := ftypes.Layer{DiffID: "sha256:abc"}

	t.Run("no setuid or setgid files", func(t *testing.T) {
		got := setuidMisconfigurations("alpine:3.20", []ftypes.FilePermission{
			{FilePath: "bin/busybox", Mode: 0o755, Layer: layer},
		})
		require.Len(t, got, 1)
		assert.Equal(t, "alpine:3.20", got[0].FilePath)
		assert.Equal(t, ftypes.FilePermissionConfig, got[0].FileType)
		assert.Empty(t, got[0].Failures)
		require.Len(t, got[0].Successes, 1)
		assert.Equal(t, SetuidCheckID, got[0].Successes[0].ID)
	})

	t.Run("setuid and setgid files", func(t *testing.T) {
		got := setuidMisconfigurations("debian:12", []ftypes.FilePermission{
			{FilePath: "usr/bin/wall", Mode: fs.ModeSetgid | 0o755, Layer: layer},
			{FilePath: "bin/ls", Mode: 0o755, Layer: layer},
			{FilePath: "usr/bin/chfn", Mode: fs.ModeSetuid | fs.ModeSetgid | 0o755, Layer: layer},
		})
		require.Len(t, got, 2)

		assert.Equal(t, "/usr/bin/chfn", got[0].FilePath)
		assert.Equal(t, layer, got[0].Layer)
		require.Len(t, got[0].Failures, 1)
		assert.Equal(t, SetuidCheckID, got[0].Failures[0].ID)
		assert.Equal(t, "File '/usr/bin/chfn' has the setuid and setgid bit set (mode ugrwxr-xr-x)", got[0].Failures[0].Message)

		assert.Equal(t, "/usr/bin/wall", got[1].FilePath)
		assert.Equal(t, "File '/usr/bin/wall' has the setgid bit set (mode grwxr-xr-x)", got[1].Failures[0].Message)
	})
}
