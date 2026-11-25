package vless

import (
	"google.golang.org/protobuf/encoding/protowire"
)

// YueConnTagField is the protobuf field number that carries the YueLink
// per-device connection tag inside the VLESS request header Addons message.
//
// Addons is a proto3 message with fields 1 (Flow) and 2 (Seed). Servers that
// decode it with google.golang.org/protobuf (Xray-core
// proxy/vless/encoding.DecodeHeaderAddons, mihomo listener/sing_vless) keep
// an unknown field in unknownFields and ignore it; mihomo's own ReadAddons
// skips unknown length-delimited fields. sing-vmess (sing-box) however
// REJECTS any field other than 1/2, so the tag is only ever sent when the
// subscription explicitly marks the proxy `yue-conn-tag: true`.
//
// 2026 is far above anything upstream has used for Addons (1, 2) and still
// encodes its tag as a 2-byte varint (the largest such field is 2047), so
// the tagged header grows by exactly 2 + 1 + len(tag) bytes.
const YueConnTagField protowire.Number = 2026

// WithYueConnTag returns an Addons that encodes exactly like addons plus one
// extra length-delimited field YueConnTagField=tag. addons itself is never
// modified (it is shared by every connection of the outbound). An empty tag
// returns addons unchanged, so the wire bytes are identical to the untagged
// build.
func WithYueConnTag(addons *Addons, tag string) *Addons {
	if tag == "" {
		return addons
	}
	out := &Addons{}
	if addons != nil {
		out.Flow = addons.Flow
		out.Seed = addons.Seed
	}
	var extra []byte
	extra = protowire.AppendTag(extra, YueConnTagField, protowire.BytesType)
	extra = protowire.AppendString(extra, tag)
	out.ProtoReflect().SetUnknown(extra)
	return out
}

// YueConnTagOf extracts the tag from raw Addons bytes (as a server would see
// them), or "" when absent. Used by tests and by the server-side spec.
func YueConnTagOf(raw []byte) string {
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return ""
		}
		raw = raw[n:]
		if num == YueConnTagField && typ == protowire.BytesType {
			v, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return ""
			}
			return string(v)
		}
		m := protowire.ConsumeFieldValue(num, typ, raw)
		if m < 0 {
			return ""
		}
		raw = raw[m:]
	}
	return ""
}
