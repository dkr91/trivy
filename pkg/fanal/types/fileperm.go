package types

import "io/fs"

// FilePermission holds the permission bits of a regular file found in a layer.
// It is used to detect setuid/setgid files in container images.
type FilePermission struct {
	FilePath string
	Mode     fs.FileMode
	Layer    Layer `json:",omitzero"`
}

// HasSpecialBits returns true if the setuid or setgid bit is set.
func (p FilePermission) HasSpecialBits() bool {
	return p.Mode&(fs.ModeSetuid|fs.ModeSetgid) != 0
}
