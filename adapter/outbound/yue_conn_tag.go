package outbound

import (
	"github.com/metacubex/mihomo/component/yueconntag"
	"github.com/metacubex/mihomo/transport/vless"
)

// YueLink per-device connection tag (component/yueconntag).
//
// Both helpers are the identity unless the proxy is marked
// `yue-conn-tag: true` by the subscription AND the host injected a device
// tag. That double gate is what keeps the wire bytes byte-identical to the
// untagged client for every server that did not opt in.

// yueVlessAddons adds the tag as an extra Addons protobuf field.
func yueVlessAddons(addons *vless.Addons, enabled bool) *vless.Addons {
	if !enabled {
		return addons
	}
	return vless.WithYueConnTag(addons, yueconntag.Get())
}

// yueHysteria2Password appends "#<tag>" to the Hysteria2 auth string. A
// stock Hysteria2 server would reject the suffixed string, so this is only
// ever enabled for servers that declared support.
func yueHysteria2Password(password string, enabled bool) string {
	if !enabled {
		return password
	}
	if tag := yueconntag.Get(); tag != "" {
		return password + "#" + tag
	}
	return password
}
