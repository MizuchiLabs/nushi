package nushi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientAddr(t *testing.T) {
	t.Parallel()
	pinned := []string{"172.18.0.0/16"}
	tests := []struct {
		name    string
		proxies []string
		peer    string
		xff     string
		want    string
	}{
		{"no proxy", nil, "203.0.113.5:1", "", "203.0.113.5"},
		{"a public peer cannot claim an address", nil, "203.0.113.5:1", "198.51.100.1", "203.0.113.5"},
		{"behind traefik", nil, testProxy, "198.51.100.1", "198.51.100.1"},
		{"spoofed hops on the left", nil, testProxy, "1.1.1.1, 198.51.100.1", "198.51.100.1"},
		{"a spoofed private hop", nil, testProxy, "10.0.0.1, 198.51.100.1", "198.51.100.1"},
		{"a client on the network", nil, testProxy, "192.168.1.5", "192.168.1.5"},
		{"junk on the left", nil, testProxy, "junk, 198.51.100.1", "198.51.100.1"},
		{"junk on the right", nil, testProxy, "198.51.100.1, junk", "172.18.0.2"},
		{"a mapped hop", nil, testProxy, "::ffff:198.51.100.1", "198.51.100.1"},
		{"a proxy without the header", nil, testProxy, "", "172.18.0.2"},
		{"a pinned proxy", pinned, testProxy, "198.51.100.1", "198.51.100.1"},
		{"a pinned chain", pinned, testProxy, "172.18.0.9, 198.51.100.1", "198.51.100.1"},
		{"pinning drops the private default", pinned, "192.168.1.5:1", "198.51.100.1", "192.168.1.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := newGuard(t, Config{Password: testPassword, TrustedProxies: tt.proxies})
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.peer
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			assert.Equal(t, netip.MustParseAddr(tt.want), g.clientAddr(r))
		})
	}
}
