// Package nushi guards a small app that has one owner instead of users.
//
// The owner signs in with a password or through an OIDC provider such as
// PocketID. Scripts send an API token as a bearer. The session is a signed
// cookie, so nothing is stored. Without a sign in the app only answers on
// loopback, and only to the local network under local host names.
package nushi

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	sessionPath = "/api/session"

	passwordTTL = 30 * 24 * time.Hour
	// Short, so a removal at the provider takes effect within a day. Signing in again is a quick redirect.
	oidcTTL = 24 * time.Hour

	minPasswordLen = 12
	// A token is guessed without the sign in's limit, so it has to be long.
	minTokenLen = 32
	// The client secret keys the session cookie in OIDC mode.
	minSecretLen = 16
)

// keyRounds makes a leaked cookie expensive to turn into the password. Tests lower it.
var keyRounds = 600_000

// Mode is how the owner signs in.
type Mode string

const (
	// ModeNone lets everyone in, so the app only answers on loopback.
	ModeNone Mode = "none"
	// ModePassword asks for one shared password.
	ModePassword Mode = "password"
	// ModeOIDC sends the owner to an OIDC provider.
	ModeOIDC Mode = "oidc"
)

// Config is a guard's settings. [FromEnv] reads them from the app's env vars,
// pass them to [New] when they come from somewhere else.
type Config struct {
	// Mode is picked from the other fields when empty: a password means
	// password, an issuer means OIDC, neither means none.
	Mode     Mode
	Password string
	// APITokens let scripts in as a bearer, in every mode but none. A second
	// one lets scripts move to a new token before the old one goes.
	APITokens []string

	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	// OIDCGroup is the group from the groups claim that may sign in.
	OIDCGroup string
	// PublicURL is the site root where browsers reach the app, the provider redirects back to it.
	PublicURL string

	// TrustedProxies are the IPs and ranges whose X-Forwarded-For and
	// X-Forwarded-Proto count. Empty trusts any proxy on a private network.
	TrustedProxies []string
	// TrustedHosts are extra names and IP ranges the app answers to in mode none.
	TrustedHosts []string
}

// Guard checks requests and, through [Guard.Protect], serves the sign in routes.
type Guard struct {
	name     string
	mode     Mode
	ttl      time.Duration
	password [sha256.Size]byte
	key      []byte              // signs the session cookie, nil in mode none
	tokens   [][sha256.Size]byte // sha256 of each API token
	oidc     *oidcClient
	mux      *http.ServeMux

	hostNames  map[string]bool
	hostRanges []netip.Prefix

	proxies []netip.Prefix
	pinned  bool // proxies came from the config, not from localRanges
	warned  atomic.Bool

	limiter limiter
}

type session struct {
	Mode     Mode `json:"mode"`
	SignedIn bool `json:"signedIn"`
	APIToken bool `json:"apiToken,omitzero"`
}

type problem struct {
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

// FromEnv builds the guard for the app called name from its env vars, which
// carry the name as a prefix, such as MYAPP_PASSWORD for myapp.
func FromEnv(name string) (*Guard, error) {
	prefix := strings.ToUpper(name) + "_"
	get := func(key string) string { return os.Getenv(prefix + key) }
	list := func(key string) []string { return strings.Split(get(key), ",") }
	return New(name, Config{
		Mode:             Mode(get("AUTH")),
		Password:         get("PASSWORD"),
		APITokens:        list("API_TOKEN"),
		OIDCIssuer:       get("OIDC_ISSUER"),
		OIDCClientID:     get("OIDC_CLIENT_ID"),
		OIDCClientSecret: get("OIDC_CLIENT_SECRET"),
		OIDCGroup:        get("OIDC_GROUP"),
		PublicURL:        get("PUBLIC_URL"),
		TrustedProxies:   list("TRUSTED_PROXIES"),
		TrustedHosts:     list("TRUSTED_HOSTS"),
	})
}

// New builds the guard for the app called name, which names the cookies and
// the env vars in error messages. The name may only hold a-z, 0-9 and _.
func New(name string, c Config) (*Guard, error) {
	if name == "" || strings.ContainsFunc(name, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_'
	}) {
		return nil, fmt.Errorf("the app name %q may only hold a-z, 0-9 and _", name)
	}
	g := &Guard{name: name, limiter: limiter{total: map[bool]int{}, tries: map[netip.Prefix]int{}}}
	mode, err := g.pickMode(c)
	if err != nil {
		return nil, err
	}
	g.mode = mode
	for _, t := range c.APITokens {
		if t = strings.TrimSpace(t); t == "" {
			continue
		}
		if len(t) < minTokenLen {
			return nil, fmt.Errorf("%s needs at least %d characters per token, a comma starts the next one",
				g.env("API_TOKEN"), minTokenLen)
		}
		g.tokens = append(g.tokens, sha256.Sum256([]byte(t)))
	}
	for _, e := range c.TrustedProxies {
		if e = strings.TrimSpace(e); e == "" {
			continue
		}
		p, ok := parseRange(e)
		if !ok {
			return nil, fmt.Errorf(
				"%s holds %q, it takes IPs and ranges such as 172.18.0.0/16",
				g.env("TRUSTED_PROXIES"),
				e,
			)
		}
		g.proxies = append(g.proxies, p)
	}
	g.pinned = len(g.proxies) > 0
	if !g.pinned {
		g.proxies = localRanges
	}

	g.mux = http.NewServeMux()
	g.mux.HandleFunc("GET "+sessionPath, g.session)
	g.mux.HandleFunc("DELETE "+sessionPath, g.signOut)

	switch mode {
	case ModeNone:
		g.hostNames = map[string]bool{"localhost": true}
		g.hostRanges = slices.Clone(localRanges)
		for _, e := range c.TrustedHosts {
			e = strings.ToLower(strings.TrimSpace(e))
			switch p, ok := parseRange(e); {
			case ok:
				g.hostRanges = append(g.hostRanges, p)
			case strings.ContainsAny(e, ":/"):
				return nil, fmt.Errorf("%s holds %q, it takes host names and IP ranges, no ports or URLs",
					g.env("TRUSTED_HOSTS"), e)
			case e != "":
				g.hostNames[e] = true
			}
		}
	case ModePassword:
		g.ttl = passwordTTL
		g.password = sha256.Sum256([]byte(c.Password))
		// Slow on purpose. A new password gives a new key, which ends every session.
		g.key, err = pbkdf2.Key(sha256.New, c.Password, []byte(name+" session cookie"), keyRounds, sha256.Size)
		if err != nil {
			return nil, fmt.Errorf("deriving the session key: %w", err)
		}
		g.mux.HandleFunc("POST "+sessionPath, g.signIn)
	case ModeOIDC:
		g.ttl = oidcTTL
		// The secret is random already, a new one ends every session.
		g.key, err = hkdf.Key(sha256.New, []byte(c.OIDCClientSecret), nil, name+" session cookie", sha256.Size)
		if err != nil {
			return nil, fmt.Errorf("deriving the session key: %w", err)
		}
		g.oidc = newOIDC(c)
		g.mux.HandleFunc("GET "+sessionPath+"/oidc", g.oidcStart)
		g.mux.HandleFunc("GET "+sessionPath+"/oidc/callback", g.oidcCallback)
	}
	return g, nil
}

func (g *Guard) pickMode(c Config) (Mode, error) {
	mode := c.Mode
	if mode == "" {
		switch {
		case c.Password != "" && c.OIDCIssuer != "":
			return "", fmt.Errorf("both %s and %s are set, pick one with %s",
				g.env("PASSWORD"), g.env("OIDC_ISSUER"), g.env("AUTH"))
		case c.Password != "":
			mode = ModePassword
		case c.OIDCIssuer != "":
			mode = ModeOIDC
		default:
			mode = ModeNone
		}
	}

	var missing []string
	need := func(value, key string) {
		if value == "" {
			missing = append(missing, g.env(key))
		}
	}
	switch mode {
	case ModeNone:
	case ModePassword:
		need(c.Password, "PASSWORD")
	case ModeOIDC:
		need(c.OIDCIssuer, "OIDC_ISSUER")
		need(c.OIDCClientID, "OIDC_CLIENT_ID")
		need(c.OIDCClientSecret, "OIDC_CLIENT_SECRET")
		need(c.OIDCGroup, "OIDC_GROUP")
		need(c.PublicURL, "PUBLIC_URL")
	default:
		return "", fmt.Errorf("%s is %q, it has to be none, password or oidc", g.env("AUTH"), mode)
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("%s sign in needs %s", mode, strings.Join(missing, ", "))
	}
	if mode == ModePassword && len(c.Password) < minPasswordLen {
		return "", fmt.Errorf("%s needs at least %d characters", g.env("PASSWORD"), minPasswordLen)
	}
	if mode == ModeOIDC {
		if len(c.OIDCClientSecret) < minSecretLen {
			return "", fmt.Errorf("%s needs at least %d characters", g.env("OIDC_CLIENT_SECRET"), minSecretLen)
		}
		u, err := url.Parse(c.OIDCIssuer)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return "", fmt.Errorf(
				"%s has to be the full URL of the provider, such as https://id.example.com",
				g.env("OIDC_ISSUER"),
			)
		}
		u, err = url.Parse(c.PublicURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
			(u.Path != "" && u.Path != "/") {
			return "", fmt.Errorf(
				"%s has to be the full URL of the site root, such as https://myapp.example.com",
				g.env("PUBLIC_URL"),
			)
		}
	}
	return mode, nil
}

// Mode reports how the owner signs in.
func (g *Guard) Mode() Mode {
	return g.mode
}

// Allowed reports whether r comes from the owner or a script with the API
// token. In mode none that is anyone on the local network under a trusted host name.
func (g *Guard) Allowed(r *http.Request) bool {
	if g.mode == ModeNone {
		return g.refuseOpen(r) == ""
	}
	if g.bearer(r.Header.Get("Authorization")) {
		return true
	}
	c, err := r.Cookie(g.cookieName())
	return err == nil && g.signedIn(c.Value)
}

// Require turns away requests that are not [Guard.Allowed]. Put it in front
// of the API, not the UI, the sign in page has to load.
func (g *Guard) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.Allowed(r) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeProblem(w, http.StatusUnauthorized, "sign in first")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Protect wraps the whole app. It serves the sign in routes under /api/session
// and guards everything against other sites. They must not write through the
// browser, open a WebSocket or frame the UI. In mode none it also turns away
// what came in on anything but loopback, what a proxy brought in from outside
// and unknown host names, since DNS rebinding reaches 127.0.0.1 under a page's
// own name. With a sign in the cookie never reaches such a page.
func (g *Guard) Protect(next http.Handler) http.Handler {
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == sessionPath || strings.HasPrefix(r.URL.Path, sessionPath+"/") {
			g.mux.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
	origins := http.NewCrossOriginProtection()
	guarded := origins.Handler(app)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.mode == ModeNone {
			if msg := g.refuseOpen(r); msg != "" {
				http.Error(w, msg, http.StatusForbidden)
				return
			}
		}
		w.Header().Set("X-Frame-Options", "DENY")
		// A WebSocket handshake is a GET, which the check skips. SameSite doesn't help, a subdomain is the same site.
		if r.Header.Get("Upgrade") != "" {
			asWrite := r.WithContext(r.Context())
			asWrite.Method = http.MethodPost
			if err := origins.Check(asWrite); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
		}
		guarded.ServeHTTP(w, r)
	})
}

// Listen binds addr. In mode none it only takes a loopback address, so a public
// bind fails at startup instead of with a 403 on every request.
func (g *Guard) Listen(ctx context.Context, addr string) (net.Listener, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok && !tcp.IP.IsLoopback() && g.mode == ModeNone {
		_ = ln.Close()
		return nil, fmt.Errorf("listening on %s needs a sign in, set %s or %s",
			ln.Addr(), g.env("PASSWORD"), g.env("OIDC_ISSUER"))
	}
	return ln, nil
}

// refuseOpen says why mode none turns r away, or "" when r may in.
func (g *Guard) refuseOpen(r *http.Request) string {
	// The client writes the headers checked below. The address it came in on it cannot fake.
	if tcp, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr); ok && !tcp.IP.IsLoopback() {
		return fmt.Sprintf(
			"the app has no sign in, so it only answers on loopback, set %s or %s",
			g.env("PASSWORD"),
			g.env("OIDC_ISSUER"),
		)
	}
	if outside(r) {
		return fmt.Sprintf(
			"a proxy brought this request from outside the local network and the app has no sign in, set %s or %s",
			g.env("PASSWORD"),
			g.env("OIDC_ISSUER"),
		)
	}
	if !g.trusted(r.Host) {
		return fmt.Sprintf(
			"%s is not a trusted host. If only your own network reaches that name, add it to %s, otherwise set %s or %s",
			r.Host,
			g.env("TRUSTED_HOSTS"),
			g.env("PASSWORD"),
			g.env("OIDC_ISSUER"),
		)
	}
	return ""
}

func (g *Guard) session(w http.ResponseWriter, r *http.Request) {
	signedIn := g.Allowed(r)
	writeJSON(w, http.StatusOK, session{
		Mode:     g.mode,
		SignedIn: signedIn,
		APIToken: signedIn && g.mode != ModeNone && len(g.tokens) > 0,
	})
}

func (g *Guard) signOut(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, g.sessionCookie("", -1, g.secure(r)))
	w.WriteHeader(http.StatusNoContent)
}

// startSession hands the browser a session cookie for the mode's ttl.
func (g *Guard) startSession(w http.ResponseWriter, r *http.Request) {
	value := g.sign(time.Now().Add(g.ttl).Unix())
	http.SetCookie(w, g.sessionCookie(value, int(g.ttl.Seconds()), g.secure(r)))
}

func (g *Guard) sessionCookie(value string, maxAge int, secure bool) *http.Cookie {
	//nolint:gosec // Secure follows the request, plain HTTP on a private network has to work
	return &http.Cookie{
		Name:     g.cookieName(),
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
}

func (g *Guard) cookieName() string {
	return g.name + "_session"
}

// sign builds the cookie value, the expiry in unix seconds and its MAC.
func (g *Guard) sign(expires int64) string {
	stamp := strconv.FormatInt(expires, 10)
	mac := hmac.New(sha256.New, g.key)
	mac.Write([]byte(stamp))
	return stamp + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (g *Guard) signedIn(value string) bool {
	if g.key == nil {
		return false
	}
	stamp, _, _ := strings.Cut(value, ".")
	expires, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil || time.Now().Unix() >= expires {
		return false
	}
	return hmac.Equal([]byte(value), []byte(g.sign(expires)))
}

func (g *Guard) bearer(header string) bool {
	scheme, given, _ := strings.Cut(header, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	sum := sha256.Sum256([]byte(given))
	return slices.ContainsFunc(g.tokens, func(t [sha256.Size]byte) bool {
		return subtle.ConstantTimeCompare(sum[:], t[:]) == 1
	})
}

func (g *Guard) trusted(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if a, err := netip.ParseAddr(host); err == nil {
		return inRanges(g.hostRanges, a.Unmap())
	}
	return g.hostNames[host]
}

// env names the app's env var for key, such as MYAPP_PASSWORD.
func (g *Guard) env(key string) string {
	return strings.ToUpper(g.name) + "_" + key
}

func writeProblem(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, problem{Title: http.StatusText(status), Status: status, Detail: detail})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
}
