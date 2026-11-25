//go:build linux || android

package sing_tun

import (
	"fmt"

	tun "github.com/metacubex/sing-tun"
	"golang.org/x/sys/unix"
)

func tunNewForListener(options tun.Options, borrowed bool) (tun.Tun, error) {
	if !borrowed {
		return tunNew(options)
	}
	if options.FileDescriptor < 0 {
		return nil, fmt.Errorf("invalid borrowed TUN descriptor")
	}
	// The caller pins this descriptor for the entire call. The stack owns only
	// this independent CLOEXEC duplicate, never the caller's original number.
	fd, err := unix.FcntlInt(uintptr(options.FileDescriptor), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, fmt.Errorf("duplicate borrowed TUN descriptor: %w", err)
	}
	options.FileDescriptor = fd
	// Pinned sing-tun v0.4.22's Linux external-FD branch unconditionally wraps
	// this fd in os.File and returns NativeTun, with no fallible setup after
	// adoption. From this call onward only that Tun may close the duplicate.
	// Re-audit this ownership boundary when upgrading sing-tun.
	return tunNew(options)
}
