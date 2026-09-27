package constant

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	P "path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/constant/features"
)

const Name = "mihomo"

var (
	GeositeName   = "GeoSite.dat"
	GeoipName     = "GeoIP.dat"
	ASNName       = "ASN.mmdb"
	BundleMRSName = "BundleMRS.7z"
)

// Path is used to get the configuration path
//
// on Unix systems, `$HOME/.config/mihomo`.
// on Windows, `%USERPROFILE%/.config/mihomo`.
var Path = func() *path {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir, _ = os.Getwd()
	}
	allowUnsafePath, _ := strconv.ParseBool(os.Getenv("SKIP_SAFE_PATH_CHECK"))
	if Hardened {
		// YueLink: a privileged helper runs this process on behalf of an
		// unprivileged user. The escape hatches below exist for operators
		// who own the whole machine; honouring them here would hand the
		// config author the helper's privileges.
		allowUnsafePath = false
	}
	homeDir = P.Join(homeDir, ".config", Name)

	if _, err = os.Stat(homeDir); err != nil {
		if configHome, ok := os.LookupEnv("XDG_CONFIG_HOME"); ok {
			homeDir = P.Join(configHome, Name)
		}
	}

	var safePaths []string
	safePathsEnv := os.Getenv("SAFE_PATHS")
	if Hardened {
		safePathsEnv = ""
	}
	for _, safePath := range filepath.SplitList(safePathsEnv) {
		safePath = strings.TrimSpace(safePath)
		if len(safePath) == 0 {
			continue
		}
		safePaths = append(safePaths, safePath)
	}

	return &path{homeDir: homeDir, configFile: "config.yaml", allowUnsafePath: allowUnsafePath, safePaths: safePaths}
}()

type path struct {
	homeDir         string
	configFile      string
	allowUnsafePath bool
	safePaths       []string
}

// SetHomeDir is used to set the configuration path
func SetHomeDir(root string) {
	Path.homeDir = root
}

// SetConfig is used to set the configuration file
func SetConfig(file string) {
	Path.configFile = file
}

func (p *path) HomeDir() string {
	return p.homeDir
}

func (p *path) Config() string {
	return p.configFile
}

// Resolve return a absolute path or a relative path with homedir
func (p *path) Resolve(path string) string {
	if !filepath.IsAbs(path) {
		return filepath.Join(p.HomeDir(), path)
	}
	return path
}

// IsSafePath return true if path is a subpath of homedir (or in the SAFE_PATHS environment variable)
//
// YueLink: the check is made twice — once on the lexical path and once on
// the path with every existing symlink resolved. Upstream compared the
// literal strings only, so `<home>/ruleset -> /etc` passed the check and a
// provider write to `ruleset/x` landed in /etc. When mihomo runs under a
// privileged helper that is a local privilege escalation. A path whose
// existing part cannot be resolved (dangling or looping symlink, EACCES)
// is not provably inside a safe path and is rejected.
func (p *path) IsSafePath(path string) bool {
	if p.allowUnsafePath || features.CMFA {
		return true
	}
	path = p.Resolve(path)
	for _, safePath := range p.SafePaths() {
		if !isLocalTo(safePath, path) {
			continue
		}
		if !filepath.IsAbs(path) || !filepath.IsAbs(safePath) {
			// No filesystem anchor to resolve against (an empty home dir in
			// unit tests); the lexical check is all that can be made.
			return true
		}
		realPath, ok := resolveExistingPrefix(path)
		if !ok {
			continue
		}
		realSafe, ok := resolveExistingPrefix(safePath)
		if !ok {
			continue
		}
		if isLocalTo(realSafe, realPath) {
			return true
		}
	}
	return false
}

// SafeRoot returns the safe path that contains path, and path relative to
// it, using the same double check as IsSafePath. Writers open the returned
// root with os.OpenRoot so that no component can be swapped for a link that
// escapes it between the check and the write.
func (p *path) SafeRoot(path string) (root string, rel string, ok bool) {
	path = p.Resolve(path)
	if !filepath.IsAbs(path) {
		return "", "", false
	}
	for _, safePath := range p.SafePaths() {
		if !filepath.IsAbs(safePath) || !isLocalTo(safePath, path) {
			continue
		}
		realPath, ok := resolveExistingPrefix(path)
		if !ok {
			continue
		}
		realSafe, ok := resolveExistingPrefix(safePath)
		if !ok {
			continue
		}
		if !isLocalTo(realSafe, realPath) {
			continue
		}
		// The lexical remainder, not the resolved one: the writer must see
		// (and refuse) a link in the final component, not silently write
		// to wherever it points.
		r, err := filepath.Rel(safePath, path)
		if err != nil || !filepath.IsLocal(r) {
			continue
		}
		return realSafe, r, true
	}
	return "", "", false
}

// AllowUnsafePath reports whether the operator disabled the safe path check.
func (p *path) AllowUnsafePath() bool {
	return p.allowUnsafePath || features.CMFA
}

func isLocalTo(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	return err == nil && filepath.IsLocal(rel)
}

// resolveExistingPrefix resolves every symlink in the longest existing
// prefix of path and re-appends the components that do not exist yet (they
// cannot be links). It fails when a component exists but cannot be resolved.
func resolveExistingPrefix(path string) (string, bool) {
	path = filepath.Clean(path)
	var missing []string
	for range 4096 {
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, true
		}
		if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
			// It exists (a dangling or looping link, or an entry we may not
			// traverse): where it points cannot be proven.
			return "", false
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", false
		}
		missing = append(missing, filepath.Base(path))
		path = parent
	}
	return "", false
}

func (p *path) SafePaths() []string {
	return append([]string{p.homeDir}, p.safePaths...) // add homedir to safePaths
}

func (p *path) ErrNotSafePath(path string) error {
	return ErrNotSafePath{Path: path, SafePaths: p.SafePaths()}
}

type ErrNotSafePath struct {
	Path      string
	SafePaths []string
}

func (e ErrNotSafePath) Error() string {
	return fmt.Sprintf("path is not subpath of home directory or SAFE_PATHS: %s \n allowed paths: %s", e.Path, e.SafePaths)
}

func (p *path) GetPathByHash(prefix, name string) string {
	hash := utils.MakeHash([]byte(name))
	filename := hash.String()
	return filepath.Join(p.HomeDir(), prefix, filename)
}

func (p *path) MMDB() string {
	files, err := os.ReadDir(p.homeDir)
	if err != nil {
		return ""
	}
	for _, fi := range files {
		if fi.IsDir() {
			// 目录则直接跳过
			continue
		} else {
			if strings.EqualFold(fi.Name(), "Country.mmdb") ||
				strings.EqualFold(fi.Name(), "geoip.db") ||
				strings.EqualFold(fi.Name(), "geoip.metadb") {
				GeoipName = fi.Name()
				return P.Join(p.homeDir, fi.Name())
			}
		}
	}
	return P.Join(p.homeDir, "geoip.metadb")
}

func (p *path) ASN() string {
	files, err := os.ReadDir(p.homeDir)
	if err != nil {
		return ""
	}
	for _, fi := range files {
		if fi.IsDir() {
			// 目录则直接跳过
			continue
		} else {
			if strings.EqualFold(fi.Name(), "ASN.mmdb") {
				ASNName = fi.Name()
				return P.Join(p.homeDir, fi.Name())
			}
		}
	}
	return P.Join(p.homeDir, ASNName)
}

func (p *path) BundleMRS() string {
	files, err := os.ReadDir(p.homeDir)
	if err != nil {
		return ""
	}
	for _, fi := range files {
		if fi.IsDir() {
			// 目录则直接跳过
			continue
		} else {
			if strings.EqualFold(fi.Name(), "BundleMRS.7z") {
				BundleMRSName = fi.Name()
				return P.Join(p.homeDir, fi.Name())
			}
		}
	}
	return P.Join(p.homeDir, BundleMRSName)
}

func (p *path) OldCache() string {
	return P.Join(p.homeDir, ".cache")
}

func (p *path) Cache() string {
	return P.Join(p.homeDir, "cache.db")
}

func (p *path) GeoIP() string {
	files, err := os.ReadDir(p.homeDir)
	if err != nil {
		return ""
	}
	for _, fi := range files {
		if fi.IsDir() {
			// 目录则直接跳过
			continue
		} else {
			if strings.EqualFold(fi.Name(), "GeoIP.dat") {
				GeoipName = fi.Name()
				return P.Join(p.homeDir, fi.Name())
			}
		}
	}
	return P.Join(p.homeDir, "GeoIP.dat")
}

func (p *path) GeoSite() string {
	files, err := os.ReadDir(p.homeDir)
	if err != nil {
		return ""
	}
	for _, fi := range files {
		if fi.IsDir() {
			// 目录则直接跳过
			continue
		} else {
			if strings.EqualFold(fi.Name(), "GeoSite.dat") {
				GeositeName = fi.Name()
				return P.Join(p.homeDir, fi.Name())
			}
		}
	}
	return P.Join(p.homeDir, "GeoSite.dat")
}

func (p *path) GetAssetLocation(file string) string {
	return P.Join(p.homeDir, file)
}

func (p *path) GetExecutableFullPath() string {
	exePath, err := os.Executable()
	if err != nil {
		return "mihomo"
	}
	res, _ := filepath.EvalSymlinks(exePath)
	return res
}
