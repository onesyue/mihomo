package constant

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrSymlinkTarget is returned when the final component of a write target is
// a symbolic link (or, on Windows, another reparse point).
var ErrSymlinkTarget = fmt.Errorf("refusing to write through a symbolic link")

// OpenFileBeneath opens path for writing without letting any component of it
// escape the safe path (home dir or SAFE_PATHS entry) that contains it.
//
// YueLink: upstream wrote provider/geodata files with os.WriteFile after a
// lexical IsSafePath check, which follows symlinks in every component. With
// mihomo running under a privileged helper that turned any link planted in
// the home dir into an arbitrary root file write. The write now goes through
// os.Root, whose openat-style resolution (reparse-point aware on Windows)
// cannot leave the root even if a directory is swapped for a link after the
// check, and a link in the final component is refused outright — the
// equivalent of O_NOFOLLOW.
//
// Paths outside every safe path are rejected unless the operator disabled
// the check (SKIP_SAFE_PATH_CHECK / CMFA), in which case upstream behaviour
// is kept.
func (p *path) OpenFileBeneath(path string, flag int, perm fs.FileMode) (*os.File, error) {
	root, rel, ok := p.SafeRoot(path)
	if !ok {
		if p.AllowUnsafePath() {
			if err := os.MkdirAll(filepath.Dir(p.Resolve(path)), 0o755); err != nil {
				return nil, err
			}
			return os.OpenFile(p.Resolve(path), flag, perm)
		}
		return nil, p.ErrNotSafePath(path)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	if dir := filepath.Dir(rel); dir != "." {
		if err := r.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	if fi, err := r.Lstat(rel); err == nil && fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return nil, fmt.Errorf("%s: %w", path, ErrSymlinkTarget)
	}
	return r.OpenFile(rel, flag, perm)
}

// WriteFileBeneath is os.WriteFile confined like OpenFileBeneath.
func (p *path) WriteFileBeneath(path string, data []byte, perm fs.FileMode) error {
	f, err := p.OpenFileBeneath(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}
