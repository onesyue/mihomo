package config_test

import (
	"testing"

	"github.com/metacubex/mihomo/component/yueconntag"
	. "github.com/metacubex/mihomo/config"
	_ "github.com/metacubex/mihomo/hub/executor" // provides the linknamed temporaryUpdateGeneral
)

func TestYueDeviceTagIsAppliedBeforeProxies(t *testing.T) {
	defer yueconntag.Set("")
	raw, err := UnmarshalRawConfig([]byte("yue-device-tag: AbCdEf012_-\n"))
	if err != nil {
		t.Fatal(err)
	}
	if raw.YueDeviceTag != "AbCdEf012_-" {
		t.Fatalf("raw tag = %q", raw.YueDeviceTag)
	}
	if _, err := ParseRawConfig(raw); err != nil {
		t.Fatal(err)
	}
	if got := yueconntag.Get(); got != "AbCdEf012_-" {
		t.Fatalf("device tag after parse = %q", got)
	}
	// A config without the key (e.g. a stock subscription) clears it.
	raw, _ = UnmarshalRawConfig([]byte("mode: rule\n"))
	if _, err := ParseRawConfig(raw); err != nil {
		t.Fatal(err)
	}
	if got := yueconntag.Get(); got != "" {
		t.Fatalf("tag survived a config without it: %q", got)
	}
}
