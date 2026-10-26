//go:build reliability_routing

package tunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	R "github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"
	RP "github.com/metacubex/mihomo/rules/provider"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// This input is the actual Ops ClashMeta template passed through Link's
// ConfigTemplate.process, not a hand-written duplicate of its routing rules.
// Ops030316db / Linkc53cb715; parent identity receipt records export source/log.
// Board account/node placeholders are deliberately NOT claimed as instantiated.
const cn02EffectiveSHA = "ffa9cc213f1d5198ff6e0473d2d9e1d74d0f6a5d320e214b42b57c5019fe0854"

type cn02RouteWitness struct {
	C.Proxy
	name string
	kind C.AdapterType
}

func (p *cn02RouteWitness) Name() string                     { return p.name }
func (p *cn02RouteWitness) Type() C.AdapterType              { return p.kind }
func (p *cn02RouteWitness) SupportUDP() bool                 { return true }
func (p *cn02RouteWitness) Unwrap(*C.Metadata, bool) C.Proxy { return nil }

type unavailableCN02Provider struct {
	P.RuleProvider
	name string
	t    *testing.T
}

func (p *unavailableCN02Provider) Match(*C.Metadata, C.RuleMatchHelper) bool {
	p.t.Fatalf("sample consumed unavailable generated provider %s; no empty-provider fallback is allowed", p.name)
	return false
}
func (p *unavailableCN02Provider) Name() string { return p.name }

func TestEffectiveChinaRoutingThroughActualCore(t *testing.T) {
	fixture, seedDir := os.Getenv("YUELINK_CN02_CONFIG"), os.Getenv("YUELINK_CN02_RULESET_DIR")
	require.NotEmpty(t, fixture)
	require.NotEmpty(t, seedDir)
	data, err := os.ReadFile(fixture)
	require.NoError(t, err)
	sum := sha256.Sum256(data)
	require.Equal(t, cn02EffectiveSHA, hex.EncodeToString(sum[:]))
	var doc struct {
		Rules     []string `yaml:"rules"`
		Providers map[string]struct {
			Behavior string `yaml:"behavior"`
			Format   string `yaml:"format"`
		} `yaml:"rule-providers"`
	}
	require.NoError(t, yaml.Unmarshal(data, &doc))
	require.NotEmpty(t, doc.Rules)
	oldRules, oldProxies, oldProviders, oldSubRules := rules, proxies, ruleProviders, subRules
	t.Cleanup(func() { rules, proxies, ruleProviders, subRules = oldRules, oldProxies, oldProviders, oldSubRules })
	rules = nil
	proxies = make(map[string]C.Proxy)
	ruleProviders = make(map[string]P.RuleProvider)
	subRules = nil
	RP.SetTunnel(Tunnel)
	loaded := map[string]string{}
	tempSeeds := t.TempDir()
	for name, schema := range doc.Providers {
		if schema.Format != "mrs" {
			ruleProviders[name] = &unavailableCN02Provider{name: name, t: t}
			continue
		}
		expected, ok := cn02SeedSHA[name]
		require.True(t, ok, "unidentified offline seed %s", name)
		path := filepath.Join(seedDir, name+".mrs")
		seed, err := os.ReadFile(path)
		require.NoError(t, err)
		hash := sha256.Sum256(seed)
		actual := hex.EncodeToString(hash[:])
		require.Equal(t, expected, actual, name)
		loaded[name] = actual
		behavior, err := P.ParseBehavior(schema.Behavior)
		require.NoError(t, err)
		format, err := P.ParseRuleFormat("mrs")
		require.NoError(t, err)
		local := filepath.Join(tempSeeds, name+".mrs")
		require.NoError(t, os.WriteFile(local, seed, 0600))
		provider := RP.NewRuleSetProvider(name, behavior, format, 0, resource.NewFileVehicle(local), nil, nil, R.ParseRule)
		ruleProviders[name] = provider
		require.NoError(t, provider.Initial())
		require.Positive(t, provider.Count())
		if closer, ok := provider.(io.Closer); ok {
			t.Cleanup(func() { require.NoError(t, closer.Close()) })
		}
	}
	for _, line := range doc.Rules {
		kind, payload, target, params := RC.ParseRulePayload(line, true)
		require.NotEmpty(t, target)
		rule, err := R.ParseRule(kind, payload, target, params, nil)
		require.NoError(t, err, line)
		for _, name := range rule.ProviderNames() {
			_, ok := ruleProviders[name]
			require.True(t, ok, "undeclared provider %s", name)
		}
		rules = append(rules, rule)
		// Typed route witnesses preserve target identity and UDP support. They do
		// not model live Board nodes or make any outbound connection.
		adapterType := C.Socks5
		if target == "DIRECT" {
			adapterType = C.Direct
		}
		if target == "REJECT" {
			adapterType = C.Reject
		}
		proxies[target] = &cn02RouteWitness{name: target, kind: adapterType}
	}
	cases := []struct {
		name, host, ip string
		network        C.NetWork
		port           uint16
		target         string
	}{
		{"domestic-ai-tcp", "api.deepseek.com", "1.1.1.1", C.TCP, 443, "DIRECT"},
		{"domestic-ai-udp", "api.deepseek.com", "1.1.1.1", C.UDP, 443, "DIRECT"},
		{"domestic-meeting", "meeting.tencent.com", "1.1.1.1", C.UDP, 443, "DIRECT"},
		{"lan-ipv4-tcp", "", "192.168.50.1", C.TCP, 8080, "DIRECT"},
		{"lan-ipv4-udp", "", "192.168.50.1", C.UDP, 443, "DIRECT"},
		{"lan-ipv6", "", "fd00::1", C.UDP, 443, "DIRECT"},
		{"lan-domain", "router.lan", "192.168.50.1", C.TCP, 80, "DIRECT"},
		{"foreign-ai", "api.openai.com", "1.1.1.1", C.TCP, 443, "AI"},
		{"foreign-ai-udp", "api.openai.com", "1.1.1.1", C.UDP, 443, "REJECT"},
		{"foreign-ai-dependency", "cloudcode-pa.googleapis.com", "1.1.1.1", C.TCP, 443, "AI"},
		{"foreign-office", "api.slack.com", "1.1.1.1", C.TCP, 443, "办公协作"},
		{"foreign-development", "registry-1.docker.io", "1.1.1.1", C.TCP, 443, "开发工具"},
		{"foreign-media-exception", "teams.cloud.microsoft", "52.112.0.1", C.UDP, 443, "Microsoft 365"},
		{"domestic-suffix-boundary", "notdeepseek.com", "1.1.1.1", C.UDP, 443, "REJECT"},
	}
	for _, sample := range cases {
		t.Run(sample.name, func(t *testing.T) {
			metadata := &C.Metadata{NetWork: sample.network, Host: sample.host, DstIP: netip.MustParseAddr(sample.ip), DstPort: sample.port}
			helper := C.RuleMatchHelper{ResolveIP: func() { require.True(t, metadata.DstIP.IsValid(), "unexpected unresolved destination") }}
			selected, rule, err := match(metadata, helper)
			require.NoError(t, err)
			require.NotNil(t, rule, "DIRECT default fallback cannot qualify")
			require.Equal(t, sample.target, selected.Name())
			if sample.target != "DIRECT" {
				require.NotEqual(t, C.Direct, selected.Type(), "required proxy/rejection must not pass through DIRECT")
			}
			t.Logf("CN02_ROUTE host=%s ip=%s network=%s target=%s rule=%s", sample.host, sample.ip, sample.network, sample.target, rule.RuleType())
		})
	}
	// Counterexample: accidentally inserting an unconditional DIRECT rule must
	// actually change the core's verdict, so the foreign oracle can reject it.
	original := rules
	direct, err := R.ParseRule("MATCH", "", "DIRECT", nil, nil)
	require.NoError(t, err)
	rules = append([]C.Rule{direct}, original...)
	selected, _, err := match(&C.Metadata{NetWork: C.TCP, Host: "api.openai.com", DstIP: netip.MustParseAddr("1.1.1.1"), DstPort: 443}, C.RuleMatchHelper{})
	require.NoError(t, err)
	require.Equal(t, "DIRECT", selected.Name())
	require.NotEqual(t, "AI", selected.Name())
	rules = original
	identity, err := json.Marshal(map[string]any{"effective_sha256": cn02EffectiveSHA, "seed_sha256": loaded, "cases": len(cases), "missing_generated_providers_not_consumed": []string{"work", "development", "meetings", "microsoft365", "microsoft365-ip"}})
	require.NoError(t, err)
	t.Logf("CN02_INPUTS %s", identity)
	// Reuse the round's real bootstrap DNS/HTTP/deletion-control receipt. This
	// test does not execute DNS transports, fetch providers, instantiate account
	// nodes, test all domains, or establish mainland network availability.
}

var cn02SeedSHA = map[string]string{
	"ads":         "c360259573cfb1f53e3986271d669f0c74537882a404a3c1a4f01f731563fe36",
	"ai":          "6f989fb6c782fd5f664171430c22ee3cded3a116969b4c11446d98aa8e16c8dc",
	"amazon":      "d0e58143ab4299a3f959526ab9ef463b7569242fb43b807eab4636cfe61ea825",
	"apple":       "b71932e3e8222f5906293079c0971c80a3a167eda7bb8b66c97a25823860ba6f",
	"bahamut":     "300c2587ab75671f43f5f165149ddf94aa420bb5e8ba92e643d61149a195cf8b",
	"bilibili":    "5f5329b62eb0f4f27d900f15b085e1d89dd01f21c2613835fbc76fcecf86e0b8",
	"bing":        "c3bf2c111518658e35c70f400c30e3d09e5d4bf9e9019f440772b9428bcb1426",
	"china":       "19d4f30153d06d3b0f7348ff78f907050935cb89f81b80e152bdc4ce5f249e86",
	"chinaips":    "206ad4cc22005976e8bfb50a869e5483cb81cc174a56c9a79c8a13e3e64e2eea",
	"chinamedia":  "3136f98c27ffc2fcdaab91492c39a0570cab97f1285ce9eea801c466cd4c3442",
	"discord":     "d7387b23e75ca9a93086ee7f9d398efb936c64bdbb85d97aa7dea99de2381891",
	"disney":      "5e37ddeb5f15b00eb7231d26dc98a773ad975520db53e6a3bf386303864e64b8",
	"epic":        "6fa5ef6f4bfb52078d8e9578718d33a0216ec6209e5bf702809e414e5a5d3003",
	"facebook":    "e086afea4d972fb2df8b8a37ffe079c547d32a18b8bd8482a0ebe6d06194ab43",
	"game":        "6a7fd187392bf92cd2c256fefaa7c2ec82231438d1d82b9606ae23c0e6b8f400",
	"github":      "7341027b668d966fd3a32a92efdda51af04f92e87901a3d45eb2c0e78ffef0fa",
	"globalmedia": "ece61485daf39fa896531e0878e708205f8a9d86302496951364a0f43346f2c3",
	"google":      "1ba7855f4ba81cef07ba11e10c6bd8c73c183c978bc768bd3ed30ccce22b51cf",
	"hbo":         "a0476474a2a9358112660d71e0a0f35e707614db85ca11217b2d641b1d401bfc",
	"instagram":   "561e6b0c2b760a3cf574d1e2c0b27da432b62eb9000e297b00dbc924614de73e",
	"lan":         "0f9ba48d4d0b0d192a4e7c3548486dde05e5a92e6e58e8ea8c9cc302712a1420",
	"lanips":      "076ea1da10b442f01c6fb3b86a66411727a15df69d70e8d600a8a458b07a8bb0",
	"line":        "cb553fec05e5d082ce502db4d518b594ea66eb481e0db31905ce395ebee640e4",
	"linkedin":    "52dd5fbf30eec116f731c917dd073de9e8f9e6081be9940d19fdf7d00780cbec",
	"microsoft":   "0bded45cac85b788e1671750629ea51ba3c77e2d984b688fc07b179df2da23e1",
	"netflix":     "a6fea26ce2168e069fe865f269e86e5e031a51b5b3855fe297e1bc004a3170bd",
	"notcn":       "a33f00bc247d2e7405b16e55cae0c1805dc7b8f463564e8e63da1484ec6d7b4d",
	"primevideo":  "c75b8864b1d7af5c7f1b4e1700369b9d34f4e39520836cf3d060757784d142f8",
	"proxy":       "c50a9fa1e0477f7da7af36410535a0694de6f5c78cf83255b2aa67eab307e214",
	"reddit":      "3c7c686ade3088c4781d8bee262c61603618db5b2be4e3e63607b591db7b4ebc",
	"spotify":     "7eea9d7fd6521c91f2a80ac2fc44a1d541385678c29cf0f7384d954bc23175bc",
	"steam":       "29f97832356a15e6125a601c98a7286324054fbca8b74b56e0eb43e2fb3a64aa",
	"telegram":    "ffa4d1d3e8649965e529c1c570d8add75a0d6f70aa8503ece8add841ce48c0e7",
	"telegramips": "d121af95b9aeca3d8c29b2112d5e6685b2a6716383df8ae31b5fbb3408c527b3",
	"tiktok":      "c5d78b65723b213ccc3a5f35fced54782d264250789bb0f59ba77085f301d7b3",
	"twitch":      "33e7854e6183bc9f6d8379c4e37a4411e354de9846db9b64bfe67fb539287975",
	"twitter":     "b287eac1d2a97da62e17cffddf55e0296665a289a41fba774fdba7397e6ea3f7",
	"whatsapp":    "bdcf58fcbea6c962e307aac8b452c39b55644ec02e92e29919eb69d0bd40985f",
	"youtube":     "e212b2ce9f39b30f4e2ab57da9ed0937673606bc56bb46e5d55ad7dd9af00aef",
}
