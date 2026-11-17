package local

import (
	"cmp"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

const (
	// SetuidCheckID is the ID of the check for setuid/setgid files in container images.
	// It maps to CIS Docker Benchmark control 4.8.
	SetuidCheckID = "DS-0032"

	setuidCheckNamespace = "trivy.image.fileperm"
)

var setuidCheckMetadata = ftypes.PolicyMetadata{
	ID:          SetuidCheckID,
	AVDID:       "AVD-" + SetuidCheckID,
	Aliases:     []string{"DS032", "no-setuid-setgid-files"},
	Type:        "Container Image Filesystem Check",
	Title:       "setuid and setgid permissions should be removed in the image",
	Description: "Files with the setuid or setgid bit run with the privileges of their owner or group. In a container image they can be abused for privilege escalation, so the bits should be removed unless they are required.",
	Severity:    "HIGH",
	RecommendedActions: "Remove the setuid and setgid bits from the files in the image, " +
		"e.g. 'RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + || true', " +
		"and keep them only on the files that require them.",
	References: []string{
		"https://www.cisecurity.org/benchmark/docker",
	},
}

// setuidMisconfigurations checks the files of a container image for the setuid and setgid bits.
// Each affected file results in a failure, an image without such files results in a success.
func setuidMisconfigurations(targetName string, perms []ftypes.FilePermission) []ftypes.Misconfiguration {
	special := slices.DeleteFunc(slices.Clone(perms), func(p ftypes.FilePermission) bool {
		return !p.HasSpecialBits()
	})
	slices.SortFunc(special, func(a, b ftypes.FilePermission) int {
		return cmp.Compare(a.FilePath, b.FilePath)
	})

	if len(special) == 0 {
		return []ftypes.Misconfiguration{
			{
				FileType: ftypes.FilePermissionConfig,
				FilePath: targetName,
				Successes: ftypes.MisconfResults{
					{
						Namespace:      setuidCheckNamespace,
						Query:          "data." + setuidCheckNamespace + ".deny",
						PolicyMetadata: setuidCheckMetadata,
					},
				},
			},
		}
	}

	misconfs := make([]ftypes.Misconfiguration, 0, len(special))
	for _, p := range special {
		filePath := "/" + strings.TrimLeft(p.FilePath, "/")
		misconfs = append(misconfs, ftypes.Misconfiguration{
			FileType: ftypes.FilePermissionConfig,
			FilePath: filePath,
			Layer:    p.Layer,
			Failures: ftypes.MisconfResults{
				{
					Namespace:      setuidCheckNamespace,
					Query:          "data." + setuidCheckNamespace + ".deny",
					Message:        fmt.Sprintf("File '%s' has the %s bit set (mode %s)", filePath, specialBits(p.Mode), p.Mode),
					PolicyMetadata: setuidCheckMetadata,
					CauseMetadata: ftypes.CauseMetadata{
						Resource: filePath,
					},
				},
			},
		})
	}
	return misconfs
}

func specialBits(mode fs.FileMode) string {
	var bits []string
	if mode&fs.ModeSetuid != 0 {
		bits = append(bits, "setuid")
	}
	if mode&fs.ModeSetgid != 0 {
		bits = append(bits, "setgid")
	}
	return strings.Join(bits, " and ")
}
