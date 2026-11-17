package fileperm

import (
	"io/fs"
	"os"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func fileInfo(t *testing.T, mode fs.FileMode) os.FileInfo {
	t.Helper()
	fsys := fstest.MapFS{"file": &fstest.MapFile{Mode: mode}}
	info, err := fs.Stat(fsys, "file")
	require.NoError(t, err)
	return info
}

func Test_filePermissionAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name string
		mode fs.FileMode
		want bool
	}{
		{
			name: "setuid executable",
			mode: fs.ModeSetuid | 0o755,
			want: true,
		},
		{
			name: "setgid without execute bit",
			mode: fs.ModeSetgid | 0o644,
			want: true,
		},
		{
			name: "executable",
			mode: 0o755,
			want: true,
		},
		{
			name: "non-executable",
			mode: 0o644,
			want: false,
		},
		{
			name: "setgid directory",
			mode: fs.ModeDir | fs.ModeSetgid | 0o2775,
			want: false,
		},
		{
			name: "symlink",
			mode: fs.ModeSymlink | 0o777,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := filePermissionAnalyzer{}
			assert.Equal(t, tt.want, a.Required("usr/bin/file", fileInfo(t, tt.mode)))
		})
	}
}

func Test_filePermissionAnalyzer_Analyze(t *testing.T) {
	a := filePermissionAnalyzer{}
	got, err := a.Analyze(t.Context(), analyzer.AnalysisInput{
		FilePath: "/usr/bin/passwd",
		Info:     fileInfo(t, fs.ModeSetuid|0o755),
	})
	require.NoError(t, err)
	assert.Equal(t, &analyzer.AnalysisResult{
		FilePermissions: []types.FilePermission{
			{
				FilePath: "usr/bin/passwd",
				Mode:     fs.ModeSetuid | 0o755,
			},
		},
	}, got)
}
