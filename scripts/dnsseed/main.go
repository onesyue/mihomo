// Command dnsseed verifies the two official upstream snapshots and extracts
// exactly the five protobuf groups used by YueLink's first-use DNS policy.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/metacubex/mihomo/component/geodata/router"
	"google.golang.org/protobuf/proto"
)

func read(path, digest string, list proto.Message) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != digest {
		return fmt.Errorf("upstream digest mismatch for %s", filepath.Base(path))
	}
	return proto.Unmarshal(raw, list)
}
func write(path string, m proto.Message) error {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return err
	}
	if _, err = w.Write(raw); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0644)
}
func run(sitePath, ipPath, dir string) error {
	var sites router.GeoSiteList
	var ips router.GeoIPList
	if err := read(sitePath, "de5bdc1f196e68cd1fad180becb593a0d3cdd41c372de7742dfacd0b1c8b5230", &sites); err != nil {
		return err
	}
	if err := read(ipPath, "d4ec4c5e5d5a38c1399964ea9fd8c94288426a3b31b483904b67819fc07f4466", &ips); err != nil {
		return err
	}
	groups := map[string]proto.Message{}
	for _, s := range sites.Entry {
		key := strings.ToLower(s.CountryCode)
		switch key {
		case "cn", "gfw", "private", "geolocation-!cn":
			name := "site-" + key
			if groups[name] != nil || len(s.Domain) == 0 {
				return fmt.Errorf("invalid upstream group %s", name)
			}
			groups[name] = s
		}
	}
	for _, ip := range ips.Entry {
		if strings.EqualFold(ip.CountryCode, "cn") {
			if groups["ip-cn"] != nil || len(ip.Cidr) == 0 {
				return fmt.Errorf("invalid upstream IP group CN")
			}
			groups["ip-cn"] = ip
		}
	}
	if len(groups) != 5 {
		return fmt.Errorf("expected five upstream groups, got %d", len(groups))
	}
	for name, entry := range groups {
		if err := write(filepath.Join(dir, name+".pb.gz"), entry); err != nil {
			return err
		}
	}
	return nil
}
func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: dnsseed geosite.dat geoip.dat output-directory")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
