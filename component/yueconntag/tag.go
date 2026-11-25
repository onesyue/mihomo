// Package yueconntag holds the YueLink per-device connection tag.
//
// The host (YueLink) injects a top-level `yue-device-tag: <tag>` into the
// config it hands the core. The tag is an opaque, stable, per-device value
// (11 base64url characters = 8 bytes; the host derives it one-way from an
// install secret). Outbounds attach it ONLY when the subscription marks that
// proxy with `yue-conn-tag: true` — i.e. when the server declared it can
// parse the tag. With either half missing the wire bytes are unchanged.
package yueconntag

import (
	"regexp"
	"sync/atomic"
)

var (
	current atomic.Pointer[string]
	valid   = regexp.MustCompile(`^[A-Za-z0-9_-]{8,32}$`)
)

// Set replaces the process-wide device tag. Anything that is not a plain
// base64url token of 8..32 characters clears it (fail closed: a malformed
// tag must never reach an auth string or a protocol header).
func Set(tag string) {
	if !valid.MatchString(tag) {
		tag = ""
	}
	current.Store(&tag)
}

// Get returns the current device tag or "".
func Get() string {
	if p := current.Load(); p != nil {
		return *p
	}
	return ""
}

// Valid reports whether tag has the accepted shape.
func Valid(tag string) bool { return valid.MatchString(tag) }
