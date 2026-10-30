package nushi

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testPassword = "correct horse battery"
	testToken    = "0123456789abcdef0123456789abcdef"
	testToken2   = "fedcba9876543210fedcba9876543210"
	testProxy    = "172.18.0.2:4321"
)

func init() {
	keyRounds = 1
}

func newGuard(t *testing.T, c Config) *Guard {
	t.Helper()
	g, err := New("app", c)
	require.NoError(t, err)
	return g
}

func do(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func signInRequest(password string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, sessionPath, strings.NewReader(`{"password":"`+password+`"}`))
	r.RemoteAddr = "192.0.2.1:1234"
	return r
}

func signInFrom(addr, password string) *http.Request {
	r := signInRequest(password)
	r.RemoteAddr = addr
	return r
}

// signInVia sends the sign in through a proxy on a docker network, the way Traefik would.
func signInVia(client, password string) *http.Request {
	r := signInFrom(testProxy, password)
	r.Header.Set("X-Forwarded-For", client)
	return r
}

func readSession(t *testing.T, g *Guard, cookies ...*http.Cookie) session {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, sessionPath, nil)
	r.Host = "localhost"
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := do(g.mux, r)
	require.Equal(t, http.StatusOK, w.Code)
	var s session
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &s))
	return s
}

func TestPickMode(t *testing.T) {
	t.Parallel()
	oidc := Config{
		OIDCIssuer: "https://id.example.com", OIDCClientID: "id", OIDCClientSecret: "0123456789abcdef",
		OIDCGroup: "admins", PublicURL: "https://app.example.com",
	}
	withURL := func(u string) Config { c := oidc; c.PublicURL = u; return c }
	withIssuer := func(u string) Config { c := oidc; c.OIDCIssuer = u; return c }
	tests := []struct {
		name string
		c    Config
		mode Mode
		err  string
	}{
		{"nothing is none", Config{}, ModeNone, ""},
		{"password", Config{Password: testPassword}, ModePassword, ""},
		{"issuer", oidc, ModeOIDC, ""},
		{"site root with a slash", withURL("https://app.example.com/"), ModeOIDC, ""},
		{"both", Config{Password: "pw", OIDCIssuer: "https://id.example.com"}, "", "pick one with APP_AUTH"},
		{"explicit password without one", Config{Mode: ModePassword}, "", "needs APP_PASSWORD"},
		{"short password", Config{Password: "hunter2"}, "", "APP_PASSWORD needs at least 12"},
		{"oidc without group", Config{Mode: ModeOIDC, OIDCIssuer: "x"}, "", "APP_OIDC_GROUP"},
		{"typo", Config{Mode: "pasword"}, "", "has to be none, password or oidc"},
		{"short secret", func() Config { c := oidc; c.OIDCClientSecret = "short"; return c }(), "", "at least 16"},
		{"relative url", withURL("app.example.com"), "", "full URL"},
		{"url with a path", withURL("https://app.example.com/app"), "", "site root"},
		{"issuer with a path", withIssuer("https://id.example.com/application/o/app/"), ModeOIDC, ""},
		{"issuer without a scheme", withIssuer("id.example.com"), "", "APP_OIDC_ISSUER has to be"},
		{"issuer on another scheme", withIssuer("ftp://id.example.com"), "", "APP_OIDC_ISSUER has to be"},
		{"host names and ranges", Config{TrustedHosts: []string{"app.lan", "203.0.113.0/24", ""}}, ModeNone, ""},
		{
			"host with a port",
			Config{TrustedHosts: []string{"app.lan:3000"}},
			"",
			`APP_TRUSTED_HOSTS holds "app.lan:3000"`,
		},
		{"host as a URL", Config{TrustedHosts: []string{"http://app.lan"}}, "", "no ports or URLs"},
		{"two tokens", Config{Password: testPassword, APITokens: []string{testToken, testToken2}}, ModePassword, ""},
		{"empty token", Config{Password: testPassword, APITokens: []string{""}}, ModePassword, ""},
		{
			"one short token",
			Config{Password: testPassword, APITokens: []string{testToken, "short"}},
			"",
			"APP_API_TOKEN needs at least",
		},
		{
			"proxy range",
			Config{Password: testPassword, TrustedProxies: []string{"172.18.0.0/16", " 10.0.0.5 ", ""}},
			ModePassword,
			"",
		},
		{
			"proxy by name",
			Config{Password: testPassword, TrustedProxies: []string{"traefik"}},
			"",
			`APP_TRUSTED_PROXIES holds "traefik"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g, err := New("app", tt.c)
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.mode, g.Mode())
		})
	}
}

func TestAppName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", "my-app", "MyApp", "a b"} {
		_, err := New(name, Config{})
		assert.ErrorContains(t, err, "may only hold", name)
	}
}

func TestFromEnvPassword(t *testing.T) {
	t.Setenv("APP_PASSWORD", testPassword)
	t.Setenv("APP_API_TOKEN", testToken+", "+testToken2)
	t.Setenv("APP_TRUSTED_PROXIES", "172.18.0.0/16,10.0.0.5")
	g, err := FromEnv("app")
	require.NoError(t, err)
	assert.Equal(t, ModePassword, g.Mode())
	assert.True(t, g.bearer("Bearer "+testToken))
	assert.True(t, g.bearer("Bearer "+testToken2))
	assert.Len(t, g.proxies, 2)
}

func TestFromEnvOIDC(t *testing.T) {
	t.Setenv("APP_OIDC_ISSUER", "https://id.example.com")
	t.Setenv("APP_OIDC_CLIENT_ID", "client")
	t.Setenv("APP_OIDC_CLIENT_SECRET", "0123456789abcdef")
	t.Setenv("APP_OIDC_GROUP", "admins")
	t.Setenv("APP_PUBLIC_URL", "https://app.example.com")
	g, err := FromEnv("app")
	require.NoError(t, err)
	assert.Equal(t, ModeOIDC, g.Mode())
	assert.Equal(t, "https://id.example.com", g.oidc.issuer)
	assert.Equal(t, "client", g.oidc.conf.ClientID)
	assert.Equal(t, "0123456789abcdef", g.oidc.conf.ClientSecret)
	assert.Equal(t, "admins", g.oidc.group)
	assert.Equal(t, "https://app.example.com"+callbackPath, g.oidc.conf.RedirectURL)
}

func TestFromEnvAuthPicksTheMode(t *testing.T) {
	t.Setenv("APP_AUTH", "none")
	t.Setenv("APP_PASSWORD", testPassword)
	t.Setenv("APP_TRUSTED_HOSTS", "app.lan")
	g, err := FromEnv("app")
	require.NoError(t, err)
	assert.Equal(t, ModeNone, g.Mode())
	assert.True(t, g.hostNames["app.lan"])
}

func TestFromEnvNamesTheVarItRead(t *testing.T) {
	t.Setenv("MY_APP2_PASSWORD", "hunter2")
	_, err := FromEnv("my_app2")
	require.ErrorContains(t, err, "MY_APP2_PASSWORD needs at least 12")
}

func TestFromEnvNothingSet(t *testing.T) {
	g, err := FromEnv("nushi_unset")
	require.NoError(t, err)
	assert.Equal(t, ModeNone, g.Mode())
}

func TestPasswordSignIn(t *testing.T) {
	t.Parallel()
	g := newGuard(t, Config{Password: testPassword})
	assert.False(t, readSession(t, g).SignedIn)

	w := do(g.mux, signInRequest("wrong"))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "wrong password")

	w = do(g.mux, signInRequest(testPassword))
	require.Equal(t, http.StatusNoContent, w.Code)
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "app_session", cookies[0].Name)
	assert.Equal(t, http.SameSiteStrictMode, cookies[0].SameSite)
	assert.True(t, cookies[0].HttpOnly)
	assert.False(t, cookies[0].Secure, "plain HTTP gets no Secure cookie")
	assert.Equal(t, int(passwordTTL.Seconds()), cookies[0].MaxAge)

	s := readSession(t, g, cookies[0])
	assert.True(t, s.SignedIn)
	assert.Equal(t, ModePassword, s.Mode)

	w = do(g.mux, httptest.NewRequest(http.MethodDelete, sessionPath, nil))
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, -1, w.Result().Cookies()[0].MaxAge)
}

func TestSecureCookieBehindProxy(t *testing.T) {
	t.Parallel()
	g := newGuard(t, Config{Password: testPassword})
	for peer, secure := range map[string]bool{testProxy: true, "203.0.113.5:1234": false} {
		r := signInFrom(peer, testPassword)
		r.Header.Set("X-Forwarded-Proto", "https")
		w := do(g.mux, r)
		require.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(
			t,
			secure,
			w.Result().Cookies()[0].Secure,
			"only a proxy on a private network may say HTTPS, %s",
			peer,
		)
	}
}

func TestNoPasswordRouteOutsidePasswordMode(t *testing.T) {
	t.Parallel()
	g := newGuard(t, Config{})
	assert.Equal(t, http.StatusMethodNotAllowed, do(g.mux, signInRequest("x")).Code)
}

func TestSignInLimit(t *testing.T) {
	t.Parallel()
	g := newGuard(t, Config{Password: testPassword})
	for range loginAttempts {
		assert.Equal(t, http.StatusUnauthorized, do(g.mux, signInRequest("wrong")).Code)
	}
	assert.Equal(t, http.StatusTooManyRequests, do(g.mux, signInRequest(testPassword)).Code)

	other := signInRequest(testPassword)
	other.RemoteAddr = "198.51.100.7:1"
	assert.Equal(t, http.StatusNoContent, do(g.mux, other).Code, "another client keeps its own budget")
}

func TestSignInBehindProxy(t *testing.T) {
	t.Parallel()
	g := newGuard(t, Config{Password: testPassword})
	for range loginAttempts {
		require.Equal(t, http.StatusUnauthorized, do(g.mux, signInVia("203.0.113.7", "guess")).Code)
	}
	assert.Equal(t, http.StatusTooManyRequests, do(g.mux, signInVia("203.0.113.7", testPassword)).Code)
	assert.Equal(t, http.StatusNoContent, do(g.mux, signInVia("198.51.100.9", testPassword)).Code,
		"a guesser behind the same proxy does not lock the owner out")
}

func TestSignInWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newGuard(t, Config{Password: testPassword})
		for range loginAttempts {
			require.Equal(t, http.StatusUnauthorized, do(g.mux, signInRequest("guess")).Code)
		}
		require.Equal(t, http.StatusTooManyRequests, do(g.mux, signInRequest(testPassword)).Code)
		time.Sleep(loginWindow)
		assert.Equal(t, http.StatusNoContent, do(g.mux, signInRequest(testPassword)).Code, "the budget comes back")
	})
}

func TestSignInCap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newGuard(t, Config{Password: testPassword})
		for range 3 * loginCap {
			do(g.mux, signInFrom("192.0.2.1:1234", "guess"))
		}
		for i := range loginAttempts {
			from := fmt.Sprintf("[2001:db8::%d]:1234", i+1)
			require.Equal(t, http.StatusUnauthorized, do(g.mux, signInFrom(from, "guess")).Code,
				"a client that is turned away spends nothing of the shared budget")
		}
		assert.Equal(t, http.StatusTooManyRequests, do(g.mux, signInFrom("[2001:db8::ff]:1234", testPassword)).Code,
			"an IPv6 host holds its whole /64")
		for i := range loginCap - 2*loginAttempts {
			from := fmt.Sprintf("198.51.100.%d:1234", i)
			require.Equal(t, http.StatusUnauthorized, do(g.mux, signInFrom(from, "guess")).Code)
		}
		assert.Equal(t, http.StatusTooManyRequests, do(g.mux, signInFrom("203.0.113.1:1234", testPassword)).Code,
			"a crowd guesses no faster than the cap")
		assert.Equal(t, http.StatusNoContent, do(g.mux, signInVia("192.168.1.5", testPassword)).Code,
			"the local network has its own cap")
	})
}

func TestSignInLocalCap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newGuard(t, Config{Password: testPassword})
		for i := range loginCap {
			require.Equal(t, http.StatusUnauthorized, do(g.mux, signInVia(fmt.Sprintf("10.0.0.%d", i), "guess")).Code)
		}
		assert.Equal(t, http.StatusTooManyRequests, do(g.mux, signInVia("10.0.1.1", testPassword)).Code,
			"faked local addresses still stop at the cap")
		assert.Equal(t, http.StatusNoContent, do(g.mux, signInVia("203.0.113.1", testPassword)).Code,
			"and leave the outside cap alone")
	})
}

func TestSignInRefund(t *testing.T) {
	t.Parallel()
	g := newGuard(t, Config{Password: testPassword})
	for range loginAttempts * 2 {
		require.Equal(t, http.StatusNoContent, do(g.mux, signInRequest(testPassword)).Code)
	}
}

func TestSignedCookie(t *testing.T) {
	t.Parallel()
	g := newGuard(t, Config{Password: testPassword})
	valid := g.sign(time.Now().Add(time.Hour).Unix())
	assert.True(t, g.signedIn(valid))
	assert.False(t, g.signedIn(g.sign(time.Now().Add(-time.Second).Unix())), "expired")
	assert.False(t, g.signedIn(valid[:len(valid)-2]+"xx"), "tampered MAC")
	stamp, mac, _ := strings.Cut(valid, ".")
	for name, value := range map[string]string{
		"a later expiry, old mac":   "9999999999." + mac,
		"the same expiry, bent mac": stamp + "." + strings.ToUpper(mac),
		"no mac":                    stamp,
		"not a session at all":      "hello",
	} {
		assert.False(t, g.signedIn(value), name)
	}

	other := newGuard(t, Config{Password: "another long password"})
	assert.False(t, other.signedIn(valid), "a new password ends old sessions")
}

func TestAllowed(t *testing.T) {
	t.Parallel()
	g := newGuard(t, Config{Password: testPassword, APITokens: []string{testToken, testToken2}})
	r := httptest.NewRequest(http.MethodGet, "/api/things", nil)
	assert.False(t, g.Allowed(r))

	for _, header := range []string{"Bearer " + testToken, "Bearer " + testToken2, "bearer " + testToken} {
		r.Header.Set("Authorization", header)
		assert.True(t, g.Allowed(r), header)
	}
	for _, header := range []string{"Bearer " + testToken + "x", "Basic " + testToken, testToken, "Bearer "} {
		r.Header.Set("Authorization", header)
		assert.False(t, g.Allowed(r), header)
	}

	r = httptest.NewRequest(http.MethodGet, "/api/things", nil)
	r.AddCookie(&http.Cookie{Name: "app_session", Value: g.sign(time.Now().Add(time.Hour).Unix())})
	assert.True(t, g.Allowed(r))
}

func TestModeNoneLetsEveryoneIn(t *testing.T) {
	t.Parallel()
	g := newGuard(t, Config{APITokens: []string{testToken}})
	r := httptest.NewRequest(http.MethodGet, "/api/things", nil)
	r.Host = "localhost:3000"
	assert.True(t, g.Allowed(r))
	s := readSession(t, g)
	assert.True(t, s.SignedIn)
	assert.False(t, s.APIToken, "the token means nothing without a sign in")
}

func TestSessionJSON(t *testing.T) {
	t.Parallel()
	g := newGuard(t, Config{Password: testPassword, APITokens: []string{testToken}})
	r := httptest.NewRequest(http.MethodGet, sessionPath, nil)
	assert.JSONEq(t, `{"mode": "password", "signed_in": false}`, do(g.mux, r).Body.String(),
		"only a signed in browser learns about the token")

	r = httptest.NewRequest(http.MethodGet, sessionPath, nil)
	r.AddCookie(&http.Cookie{Name: "app_session", Value: g.sign(time.Now().Add(time.Hour).Unix())})
	assert.JSONEq(t, `{"mode": "password", "signed_in": true, "api_token": true}`, do(g.mux, r).Body.String())
}

func TestRequire(t *testing.T) {
	t.Parallel()
	g := newGuard(t, Config{Password: testPassword})
	h := g.Require(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	w := do(h, httptest.NewRequest(http.MethodGet, "/api/things", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "application/problem+json", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), `"detail":"sign in first"`)
}

func TestProtectHosts(t *testing.T) {
	t.Parallel()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	g := newGuard(t, Config{TrustedHosts: []string{"app.lan", "203.0.113.0/24"}})
	open := g.Protect(ok)
	tests := []struct {
		host string
		code int
	}{
		{"localhost:3000", http.StatusOK},
		{"127.0.0.1:3000", http.StatusOK},
		{"[::1]:3000", http.StatusOK},
		{"192.168.1.5", http.StatusOK},
		{"APP.lan", http.StatusOK},
		{"203.0.113.9", http.StatusOK},
		{"LOCALHOST", http.StatusOK},
		{"[::ffff:10.0.0.5]:3000", http.StatusOK},
		{"evil.example.com", http.StatusForbidden},
		{"localhost.evil.example", http.StatusForbidden},
		{"", http.StatusForbidden},
		{"8.8.8.8", http.StatusForbidden},
	}
	for _, tt := range tests {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = tt.host
		w := do(open, r)
		assert.Equal(t, tt.code, w.Code, tt.host)
		assert.Equal(t, tt.code == http.StatusOK, g.Allowed(r), "Allowed agrees with Protect for %q", tt.host)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "evil.example.com"
	w := do(newGuard(t, Config{Password: testPassword}).Protect(ok), r)
	assert.Equal(t, http.StatusOK, w.Code, "with a sign in any host may ask")
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
}

func TestProtectOutside(t *testing.T) {
	t.Parallel()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	g := newGuard(t, Config{TrustedHosts: []string{"app.example.com"}, TrustedProxies: []string{"127.0.0.1"}})
	tests := []struct {
		header, value string
		code          int
	}{
		{"X-Forwarded-For", "203.0.113.5", http.StatusForbidden},
		{"X-Forwarded-For", "192.168.1.10, 203.0.113.5", http.StatusForbidden},
		{"X-Forwarded-For", "203.0.113.5, 192.168.1.10", http.StatusForbidden},
		{"X-Forwarded-For", "not-an-address", http.StatusForbidden},
		{"Forwarded", "for=127.0.0.1", http.StatusForbidden},
		{"X-Forwarded-For", "::1", http.StatusOK},
		{"X-Forwarded-For", "::ffff:127.0.0.1", http.StatusOK},
		{"X-Forwarded-For", "192.168.1.10", http.StatusOK},
	}
	for _, tt := range tests {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = "app.example.com"
		r.RemoteAddr = "127.0.0.1:5555"
		r.Header.Set(tt.header, tt.value)
		w := do(g.Protect(ok), r)
		assert.Equal(t, tt.code, w.Code, "%s: %s", tt.header, tt.value)
		assert.Equal(t, tt.code == http.StatusOK, g.Allowed(r), "%s: %s", tt.header, tt.value)
		if tt.code == http.StatusForbidden {
			assert.Contains(t, w.Body.String(), "set APP_PASSWORD or APP_OIDC_ISSUER")
		}
	}
}

func TestProtectCrossOrigin(t *testing.T) {
	t.Parallel()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := newGuard(t, Config{Password: testPassword}).Protect(ok)
	for _, path := range []string{"/api/things", sessionPath} {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		assert.Equal(t, http.StatusForbidden, do(h, r).Code, path)
	}
}

func TestProtectWebSocket(t *testing.T) {
	t.Parallel()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	tests := []struct {
		name, origin, site string
		code               int
	}{
		{"another site", "https://evil.example", "cross-site", http.StatusForbidden},
		{"a subdomain, which keeps the Strict cookie", "https://other.localhost", "same-site", http.StatusForbidden},
		{"another site on an older browser", "https://evil.example", "", http.StatusForbidden},
		{"the app itself", "http://localhost:3000", "same-origin", http.StatusOK},
		{"the app on an older browser", "http://localhost:3000", "", http.StatusOK},
		{"a script", "", "", http.StatusOK},
	}
	for _, c := range []Config{{}, {Password: testPassword}} {
		g := newGuard(t, c)
		for _, tt := range tests {
			r := httptest.NewRequest(http.MethodGet, "/ws", nil)
			r.Host = "localhost:3000"
			r.Header.Set("Upgrade", "websocket")
			r.Header.Set("Origin", tt.origin)
			r.Header.Set("Sec-Fetch-Site", tt.site)
			assert.Equal(t, tt.code, do(g.Protect(ok), r).Code, "%s, mode %s", tt.name, g.Mode())
		}
	}
}

func TestProtectServesSessionRoutes(t *testing.T) {
	t.Parallel()
	app := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := newGuard(t, Config{Password: testPassword}).Protect(app)
	tests := []struct {
		path string
		code int
	}{
		{sessionPath, http.StatusOK},
		{sessionPath + "/oidc", http.StatusNotFound},
		{sessionPath + "s", http.StatusTeapot},
		{"/api/things", http.StatusTeapot},
		{"/", http.StatusTeapot},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.code, do(h, httptest.NewRequest(http.MethodGet, tt.path, nil)).Code, tt.path)
	}
	assert.Equal(t, http.StatusNoContent, do(h, signInRequest(testPassword)).Code)
}

func TestModeNoneOnlyAnswersOnLoopback(t *testing.T) {
	t.Parallel()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	g := newGuard(t, Config{})
	tests := []struct {
		name string
		addr net.Addr
		code int
	}{
		{"ipv4 loopback", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, http.StatusOK},
		{"ipv6 loopback", &net.TCPAddr{IP: net.IPv6loopback}, http.StatusOK},
		{"the local network", &net.TCPAddr{IP: net.IPv4(192, 168, 1, 5)}, http.StatusForbidden},
		{"a public address", &net.TCPAddr{IP: net.IPv4(203, 0, 113, 5)}, http.StatusForbidden},
		{"a unix socket", &net.UnixAddr{Name: "/run/app.sock", Net: "unix"}, http.StatusOK},
	}
	for _, tt := range tests {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = "localhost"
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, tt.addr))
		w := do(g.Protect(ok), r)
		assert.Equal(t, tt.code, w.Code, tt.name)
		assert.Equal(t, tt.code == http.StatusOK, g.Allowed(r), "Allowed agrees with Protect for %s", tt.name)
		if tt.code == http.StatusForbidden {
			assert.Contains(t, w.Body.String(), "set APP_PASSWORD or APP_OIDC_ISSUER")
		}
	}
}

func TestModeNoneOnARealLoopbackServer(t *testing.T) {
	t.Parallel()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := httptest.NewServer(newGuard(t, Config{}).Protect(ok))
	t.Cleanup(srv.Close)
	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(r)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestListen(t *testing.T) {
	t.Parallel()
	open := newGuard(t, Config{})
	ln, err := open.Listen(t.Context(), "127.0.0.1:0")
	require.NoError(t, err)
	_ = ln.Close()

	_, err = open.Listen(t.Context(), "0.0.0.0:0")
	require.ErrorContains(t, err, "needs a sign in, set APP_PASSWORD or APP_OIDC_ISSUER")

	ln, err = newGuard(t, Config{Password: testPassword}).Listen(t.Context(), "0.0.0.0:0")
	require.NoError(t, err)
	_ = ln.Close()
}
