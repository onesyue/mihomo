package outboundgroup

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"

	"github.com/metacubex/mihomo/common/atomic"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type SelectorOption struct {
	DefaultSelected string `group:"default-selected,omitempty"`
}

type Selector struct {
	*GroupBase
	disableUDP        bool
	selected          atomic.TypedValue[string]
	selectionMu       sync.Mutex
	selectionRevision string
	selectionRetired  bool
	testUrl           string
}

// DialContext implements C.ProxyAdapter
func (s *Selector) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := s.selectedProxy(true).DialContext(ctx, metadata)
	if err == nil {
		c.AppendToChains(s)
	}
	return c, err
}

// ListenPacketContext implements C.ProxyAdapter
func (s *Selector) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	pc, err := s.selectedProxy(true).ListenPacketContext(ctx, metadata)
	if err == nil {
		pc.AppendToChains(s)
	}
	return pc, err
}

// SupportUDP implements C.ProxyAdapter
func (s *Selector) SupportUDP() bool {
	if s.disableUDP {
		return false
	}

	return s.selectedProxy(false).SupportUDP()
}

// IsL3Protocol implements C.ProxyAdapter
func (s *Selector) IsL3Protocol(metadata *C.Metadata) bool {
	return s.selectedProxy(false).IsL3Protocol(metadata)
}

// MarshalJSON implements C.ProxyAdapter
func (s *Selector) MarshalJSON() ([]byte, error) {
	all := []string{}
	for _, proxy := range s.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	// When testurl is the default value
	// do not append a value to ensure that the web dashboard follows the settings of the dashboard
	var url string
	if s.testUrl != C.DefaultTestURL {
		url = s.testUrl
	}

	return json.Marshal(map[string]any{
		"type":          s.Type().String(),
		"now":           s.Now(),
		"all":           all,
		"testUrl":       url,
		"hidden":        s.Hidden(),
		"icon":          s.Icon(),
		"emptyFallback": s.EmptyFallback().Name(),
	})
}

func (s *Selector) Now() string {
	return s.selectedProxy(false).Name()
}

// ErrSelectionChanged signals that a conditional control update no longer owns
// the selected member, or that the configuration replaced this selector.
var ErrSelectionChanged = errors.New("selector revision changed")

// SelectionRevision is the current version of this instance's control state.
func (s *Selector) SelectionRevision() string {
	s.selectionMu.Lock()
	defer s.selectionMu.Unlock()
	return s.selectionRevision
}

// UpdateSelection validates the revision, changes the member, and records the
// choice before another control operation may enter this selector. Data-plane
// lookups only load the current selection and never wait for the disk write.
func (s *Selector) UpdateSelection(name string, matches func(string) bool, persist func()) (string, error) {
	s.selectionMu.Lock()
	defer s.selectionMu.Unlock()
	if s.selectionRetired || (matches != nil && !matches(s.selectionRevision)) {
		return "", ErrSelectionChanged
	}
	for _, proxy := range s.GetProxies(false) {
		if proxy.Name() == name {
			s.selected.Store(name)
			s.selectionRevision = rand.Text()
			if persist != nil {
				persist()
			}
			return s.selectionRevision, nil
		}
	}
	return "", errors.New("proxy not exist")
}

func (s *Selector) Set(name string) error {
	_, err := s.UpdateSelection(name, nil, nil)
	return err
}

func (s *Selector) ForceSet(name string) {
	s.selectionMu.Lock()
	defer s.selectionMu.Unlock()
	if !s.selectionRetired {
		s.selected.Store(name)
		s.selectionRevision = rand.Text()
	}
}

// RetireSelection fences handlers which resolved this adapter before a reload.
// Existing connections retain their data-plane selection.
func (s *Selector) RetireSelection() {
	s.selectionMu.Lock()
	defer s.selectionMu.Unlock()
	s.selectionRetired = true
}

// Unwrap implements C.ProxyAdapter
func (s *Selector) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return s.selectedProxy(touch)
}

func (s *Selector) selectedProxy(touch bool) C.Proxy {
	proxies := s.GetProxies(touch)
	selected := s.selected.Load()
	for _, proxy := range proxies {
		if proxy.Name() == selected {
			return proxy
		}
	}

	return proxies[0]
}

func (s *Selector) Providers() []P.ProxyProvider {
	return s.providers
}

func (s *Selector) Proxies() []C.Proxy {
	return s.GetProxies(false)
}

func NewSelector(option GroupCommonOption, selectorOption SelectorOption, emptyFallback C.Proxy, providers []P.ProxyProvider) (*Selector, error) {
	return &Selector{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:           option.Name,
			Type:           C.Selector,
			Hidden:         option.Hidden,
			Icon:           option.Icon,
			Filter:         option.Filter,
			ExcludeFilter:  option.ExcludeFilter,
			ExcludeType:    option.ExcludeType,
			TestTimeout:    option.TestTimeout,
			MaxFailedTimes: option.MaxFailedTimes,
			EmptyFallback:  emptyFallback,
			Providers:      providers,
		}),
		selected:          atomic.NewTypedValue(selectorOption.DefaultSelected),
		selectionRevision: rand.Text(),
		disableUDP:        option.DisableUDP,
		testUrl:           option.URL,
	}, nil
}
