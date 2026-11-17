package applier_test

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestApplyLayers_FilePermissions(t *testing.T) {
	layers := []types.BlobInfo{
		{
			SchemaVersion: types.BlobJSONSchemaVersion,
			DiffID:        "sha256:base",
			FilePermissions: []types.FilePermission{
				{FilePath: "usr/bin/passwd", Mode: fs.ModeSetuid | 0o755},
				{FilePath: "usr/bin/su", Mode: fs.ModeSetuid | 0o755},
				{FilePath: "usr/bin/wall", Mode: fs.ModeSetgid | 0o755},
			},
		},
		{
			// e.g. RUN chmod a-s /usr/bin/passwd && rm /usr/bin/su
			SchemaVersion: types.BlobJSONSchemaVersion,
			DiffID:        "sha256:upper",
			CreatedBy:     "RUN chmod a-s /usr/bin/passwd && rm /usr/bin/su",
			WhiteoutFiles: []string{"usr/bin/su"},
			FilePermissions: []types.FilePermission{
				{FilePath: "usr/bin/passwd", Mode: 0o755},
			},
		},
	}

	got := applier.ApplyLayers(layers)
	assert.ElementsMatch(t, []types.FilePermission{
		{
			FilePath: "usr/bin/passwd",
			Mode:     0o755,
			Layer: types.Layer{
				DiffID:    "sha256:upper",
				CreatedBy: "RUN chmod a-s /usr/bin/passwd && rm /usr/bin/su",
			},
		},
		{
			FilePath: "usr/bin/wall",
			Mode:     fs.ModeSetgid | 0o755,
			Layer: types.Layer{
				DiffID: "sha256:base",
			},
		},
	}, got.FilePermissions)
}
