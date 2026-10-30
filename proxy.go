package nushi

import (
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// localRanges are this machine and the private networks around it, Tailscale included.
var localRanges = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// clientAddr is who sent r. Behind a trusted proxy it is the last hop the proxies do not vouch for.
func (g *Guard) clientAddr(r *http.Request) netip.Addr {
	addr := peer(r)
	if !g.viaProxy(r) {
		return addr
	}
	for _, hop := range slices.Backward(forwardedFor(r)) {
		if !hop.IsValid() {
			break
		}
		addr = hop
		if !inRanges(g.proxies, hop) {
			break
		}
	}
	return addr
}

// viaProxy reports whether r's direct peer is a trusted proxy. It warns once about a proxy that is not pinned.
func (g *Guard) viaProxy(r *http.Request) bool {
	if g.mode == ModeNone {
		return false
	}
	p := peer(r)
	trusted := inRanges(g.proxies, p)
	if (!g.pinned || !trusted) && local(p) && r.Header.Get("X-Forwarded-For") != "" &&
		g.warned.CompareAndSwap(false, true) {
		msg := "trusting a proxy on a private network, pin its docker network subnet with " + g.env("TRUSTED_PROXIES")
		if g.pinned {
			msg = "a proxy that is not in " + g.env("TRUSTED_PROXIES") + " sends forwarded headers, they are ignored"
		}
		slog.Warn(msg, "proxy", p)
	}
	return trusted
}

// secure reports whether the browser reached us over HTTPS. A trusted proxy that ends TLS says so in a header.
func (g *Guard) secure(r *http.Request) bool {
	return r.TLS != nil || (g.viaProxy(r) && r.Header.Get("X-Forwarded-Proto") == "https")
}

// outside reports whether a proxy says r comes from beyond the local network. It ignores
// TrustedProxies on purpose, pinning a proxy must never open mode none.
func outside(r *http.Request) bool {
	return r.Header.Get("Forwarded") != "" ||
		slices.ContainsFunc(forwardedFor(r), func(a netip.Addr) bool { return !local(a) })
}

// forwardedFor lists the X-Forwarded-For hops, oldest first. A hop that is no address is the zero Addr.
func forwardedFor(r *http.Request) []netip.Addr {
	var hops []netip.Addr
	for _, line := range r.Header.Values("X-Forwarded-For") {
		for hop := range strings.SplitSeq(line, ",") {
			a, _ := netip.ParseAddr(strings.TrimSpace(hop))
			hops = append(hops, a.Unmap())
		}
	}
	return hops
}

func peer(r *http.Request) netip.Addr {
	ap, _ := netip.ParseAddrPort(r.RemoteAddr)
	return ap.Addr().Unmap()
}

func local(a netip.Addr) bool {
	return inRanges(localRanges, a)
}

func inRanges(ranges []netip.Prefix, a netip.Addr) bool {
	return slices.ContainsFunc(ranges, func(p netip.Prefix) bool { return p.Contains(a) })
}

// parseRange reads an IP or a CIDR range.
func parseRange(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}
