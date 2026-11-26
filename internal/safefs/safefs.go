// Package safefs reads the repository's own files (rules, manifests, corpora, specs) with the limits the standard asks for at every
// input boundary: a size cap, no symlinks, no directories, and a relative path from a manifest that cannot leave its root
// (SSPL-NFR SEC-09, GO-14). Nothing here is specific to rules; it exists so the gate packages share one reader instead of each
// calling os.ReadFile.
package safefs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// MaxFileBytes is the largest file any gate reads. The largest real file in the repository is about 12 KB; this leaves a very wide
// margin and still stops a runaway or hostile file from being loaded whole.
const MaxFileBytes = 4 << 20

// ReadFile reads path like os.ReadFile, but refuses a symlink, anything that is not a regular file, and a file over MaxFileBytes.
// A missing file still satisfies errors.Is(err, os.ErrNotExist), with the same error os.ReadFile gives.
func ReadFile(path string) ([]byte, error) { return ReadFileMax(path, MaxFileBytes) }

// ReadFileMax is ReadFile with an explicit limit.
func ReadFileMax(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if li, err := os.Lstat(path); err != nil {
		return nil, err
	} else if li.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("safefs: %s is a symbolic link", path)
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("safefs: %s is not a regular file", path)
	}
	if fi.Size() > limit {
		return nil, fmt.Errorf("safefs: %s is %d bytes, over the %d byte limit", path, fi.Size(), limit)
	}
	// The file may have grown since Stat: read at most one byte more than the limit and refuse it.
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("safefs: %s grew past the %d byte limit while it was read", path, limit)
	}
	return data, nil
}

// Join returns root joined with a slash-separated relative path taken from a manifest, spec or other data file. It refuses an
// absolute path, a path with ".." that leaves root, and an empty one.
func Join(root, rel string) (string, error) {
	local := filepath.FromSlash(rel)
	if rel == "" || !filepath.IsLocal(local) {
		return "", fmt.Errorf("safefs: %q is not a path inside %s", rel, root)
	}
	return filepath.Join(root, local), nil
}
