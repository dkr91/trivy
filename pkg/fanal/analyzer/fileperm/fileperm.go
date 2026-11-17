// Package fileperm records the permission bits of regular files
// so that setuid/setgid files can be detected in container images.
package fileperm

import (
	"context"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&filePermissionAnalyzer{})
}

const version = 1

// filePermissionAnalyzer records the mode of executable files and of files with the setuid/setgid bit.
//
// Executables without special bits are recorded as well: an upper layer that re-adds
// a file without the setuid/setgid bit (e.g. "RUN find / -perm /6000 -exec chmod a-s {} +")
// must replace the finding from a lower layer when the layers are merged.
//
// The analyzer only looks at the file metadata, the content is never read.
type filePermissionAnalyzer struct{}

func (a filePermissionAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	return &analyzer.AnalysisResult{
		FilePermissions: []types.FilePermission{
			{
				FilePath: path.Clean(strings.TrimLeft(input.FilePath, "/")),
				Mode:     input.Info.Mode(),
			},
		},
	}, nil
}

func (a filePermissionAnalyzer) Required(_ string, info os.FileInfo) bool {
	mode := info.Mode()
	if !mode.IsRegular() {
		return false
	}
	return mode&0o111 != 0 || mode&(fs.ModeSetuid|fs.ModeSetgid) != 0
}

// MetadataOnly tells the analyzer group not to open the file content.
func (a filePermissionAnalyzer) MetadataOnly() bool {
	return true
}

func (a filePermissionAnalyzer) Type() analyzer.Type {
	return analyzer.TypeFilePermission
}

func (a filePermissionAnalyzer) Version() int {
	return version
}
