//go:build darwin

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
	return newBorrowedDarwinTun(options, tunNew)
}

func newBorrowedDarwinTun(options tun.Options, factory func(tun.Options) (tun.Tun, error)) (tun.Tun, error) {
	if options.MTU == 0 {
		return nil, fmt.Errorf("borrowed TUN MTU must be positive")
	}
	fd, err := unix.FcntlInt(uintptr(options.FileDescriptor), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, fmt.Errorf("duplicate borrowed TUN descriptor: %w", err)
	}
	options.FileDescriptor = fd
	device, err := factory(options)
	if err != nil {
		// Pinned v0.4.22 Darwin external-FD errors occur in configure(), before
		// os.NewFile adopts the fd. A returned error therefore leaves this dup
		// here; success transfers it to NativeTun. Do not infer this from fcntl.
		_ = unix.Close(fd)
	}
	return device, err
}
