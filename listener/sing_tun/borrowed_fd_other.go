//go:build !linux && !android && !darwin

package sing_tun

import (
	"errors"

	tun "github.com/metacubex/sing-tun"
)

func tunNewForListener(options tun.Options, borrowed bool) (tun.Tun, error) {
	if borrowed {
		return nil, errors.New("borrowed TUN descriptors require Linux or Android")
	}
	return tunNew(options)
}
