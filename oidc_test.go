package nushi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testClientID = "app-client"
	testCode     = "good-code"
)

// fakeProvider answers discovery, keys and the token exchange like PocketID would.
type fakeProvider struct {
	srv  *httptest.Server
	key  *ecdsa.PrivateKey
	down atomic.Bool

	mu        sync.Mutex
	challenge string
	nonce     string
	claims    map[string]any // merged over the defaults
	info      map[string]any // what userinfo answers, nil for a 404
}

func newProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	idp := &fakeProvider{key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		if idp.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                idp.srv.URL,
			"authorization_endpoint":                idp.srv.URL + "/authorize",
			"token_endpoint":                        idp.srv.URL + "/token",
			"jwks_uri":                              idp.srv.URL + "/jwks",
			"userinfo_endpoint":                     idp.srv.URL + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"ES256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"},
		}})
	})
	mux.HandleFunc("POST /token", idp.token)
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		defer idp.mu.Unlock()
		if idp.info == nil || r.Header.Get("Authorization") != "Bearer at" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, idp.info)
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func (idp *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
	if r.PostFormValue("code") != testCode || base64.RawURLEncoding.EncodeToString(sum[:]) != idp.challenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	claims := map[string]any{
		"iss":    idp.srv.URL,
		"sub":    "owner",
		"aud":    testClientID,
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(5 * time.Minute).Unix(),
		"nonce":  idp.nonce,
		"groups": []string{"admins"},
	}
	maps.Copy(claims, idp.claims)
	payload, _ := json.Marshal(claims)
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: idp.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"),
	)
	jws, _ := signer.Sign(payload)
	idToken, _ := jws.CompactSerialize()
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": idToken,
	})
}

func oidcGuard(t *testing.T, idp *fakeProvider) *Guard {
	t.Helper()
	return newGuard(t, Config{
		OIDCIssuer:       idp.srv.URL,
		OIDCClientID:     testClientID,
		OIDCClientSecret: "0123456789abcdef0123456789abcdef",
		OIDCGroup:        "admins",
		PublicURL:        "http://app.example.com/",
	})
}

// start begins a sign in and hands back the provider's query and the flow cookie.
func start(t *testing.T, g *Guard, idp *fakeProvider) (url.Values, *http.Cookie) {
	t.Helper()
	w := do(g.mux, httptest.NewRequest(http.MethodGet, sessionPath+"/oidc", nil))
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, idp.srv.URL+"/authorize", loc.Scheme+"://"+loc.Host+loc.Path)
	q := loc.Query()

	idp.mu.Lock()
	idp.challenge, idp.nonce = q.Get("code_challenge"), q.Get("nonce")
	idp.mu.Unlock()

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite)
	return q, cookies[0]
}

func callback(g *Guard, query string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, callbackPath+"?"+query, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return do(g.mux, r)
}

func findCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestOIDCSignIn(t *testing.T) {
	t.Parallel()
	idp := newProvider(t)
	g := oidcGuard(t, idp)
	assert.Equal(t, ModeOIDC, readSession(t, g).Mode)

	q, flow := start(t, g, idp)
	assert.Equal(t, testClientID, q.Get("client_id"))
	assert.Equal(t, "http://app.example.com"+callbackPath, q.Get("redirect_uri"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Contains(t, q.Get("scope"), "groups")

	w := callback(g, "code="+testCode+"&state="+q.Get("state"), flow)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `http-equiv="refresh"`)

	assert.Equal(t, -1, findCookie(w, "app_oidc").MaxAge, "the flow cookie is spent")
	session := findCookie(w, "app_session")
	require.NotNil(t, session)
	assert.Equal(t, int(oidcTTL.Seconds()), session.MaxAge)
	assert.True(t, readSession(t, g, session).SignedIn)
}

func TestOIDCThroughProtect(t *testing.T) {
	t.Parallel()
	idp := newProvider(t)
	g := oidcGuard(t, idp)
	q, flow := start(t, g, idp)
	r := httptest.NewRequest(http.MethodGet, callbackPath+"?code="+testCode+"&state="+q.Get("state"), nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.AddCookie(flow)
	w := do(g.Protect(http.NotFoundHandler()), r)
	assert.Equal(t, http.StatusOK, w.Code, "the provider's redirect is a cross-site navigation")
	assert.NotNil(t, findCookie(w, "app_session"))
}

func TestOIDCNoFlowCookie(t *testing.T) {
	t.Parallel()
	idp := newProvider(t)
	g := oidcGuard(t, idp)
	q, _ := start(t, g, idp)
	w := callback(g, "code="+testCode+"&state="+q.Get("state"), nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "took too long")
}

func TestOIDCStateMismatch(t *testing.T) {
	t.Parallel()
	idp := newProvider(t)
	g := oidcGuard(t, idp)
	_, flow := start(t, g, idp)
	w := callback(g, "code="+testCode+"&state=other", flow)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "does not match")
	assert.Nil(t, findCookie(w, "app_oidc"), "a stray link leaves the sign in in progress alone")
}

func TestOIDCProviderError(t *testing.T) {
	t.Parallel()
	idp := newProvider(t)
	g := oidcGuard(t, idp)
	q, flow := start(t, g, idp)
	const said = "error=access_denied&error_description=user+said+no"

	w := callback(g, said, flow)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NotContains(t, w.Body.String(), "user said no", "without the state anyone could write that text")

	w = callback(g, said+"&state="+q.Get("state"), flow)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "user said no")
	assert.Equal(t, -1, findCookie(w, "app_oidc").MaxAge)
}

func TestOIDCWrongVerifier(t *testing.T) {
	t.Parallel()
	idp := newProvider(t)
	g := oidcGuard(t, idp)
	q, flow := start(t, g, idp)
	head, _, _ := strings.CutLast(flow.Value, ".")
	flow.Value = head + ".forged"
	w := callback(g, "code="+testCode+"&state="+q.Get("state"), flow)
	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Contains(t, w.Body.String(), "did not take")
	assert.NotContains(t, w.Body.String(), "invalid_grant", "the provider's answer goes to the log")
}

func TestOIDCRejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		claims map[string]any
		code   int
		msg    string
	}{
		{
			name:   "nonce mismatch",
			claims: map[string]any{"nonce": "other"},
			code:   http.StatusUnauthorized,
			msg:    "another sign in",
		},
		{
			name:   "wrong group",
			claims: map[string]any{"groups": []string{"family"}},
			code:   http.StatusForbidden,
			msg:    "admins",
		},
		{name: "no groups", claims: map[string]any{"groups": nil}, code: http.StatusForbidden, msg: "admins"},
		{
			name:   "expired",
			claims: map[string]any{"exp": time.Now().Add(-time.Hour).Unix()},
			code:   http.StatusUnauthorized, msg: "not valid",
		},
		{
			name:   "other audience",
			claims: map[string]any{"aud": "someone-else"},
			code:   http.StatusUnauthorized,
			msg:    "not valid",
		},
		{
			name:   "other issuer",
			claims: map[string]any{"iss": "https://evil.example.com"},
			code:   http.StatusUnauthorized,
			msg:    "not valid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newProvider(t)
			idp.claims = tt.claims
			g := oidcGuard(t, idp)
			q, flow := start(t, g, idp)
			w := callback(g, "code="+testCode+"&state="+q.Get("state"), flow)
			assert.Equal(t, tt.code, w.Code)
			assert.Contains(t, w.Body.String(), tt.msg)
			assert.NotContains(t, w.Body.String(), "oidc:", "go-oidc's error goes to the log")
			assert.Nil(t, findCookie(w, "app_session"), "no session on a failed sign in")
		})
	}
}

func TestOIDCGroupsFromUserinfo(t *testing.T) {
	t.Parallel()
	for name, tt := range map[string]struct {
		info map[string]any
		code int
	}{
		"in the group":    {map[string]any{"sub": "owner", "groups": []string{"admins"}}, http.StatusOK},
		"another subject": {map[string]any{"sub": "someone", "groups": []string{"admins"}}, http.StatusForbidden},
		"no userinfo":     {nil, http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			idp := newProvider(t)
			idp.claims = map[string]any{"groups": nil}
			idp.info = tt.info
			g := oidcGuard(t, idp)
			q, flow := start(t, g, idp)
			w := callback(g, "code="+testCode+"&state="+q.Get("state"), flow)
			assert.Equal(t, tt.code, w.Code, w.Body.String())
		})
	}
}

func TestOIDCWithoutGroup(t *testing.T) {
	t.Parallel()
	for name, groups := range map[string]any{
		"no groups claim": nil,
		"other groups":    []string{"family"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			idp := newProvider(t)
			idp.claims = map[string]any{"groups": groups}
			g := newGuard(t, Config{
				OIDCIssuer:       idp.srv.URL,
				OIDCClientID:     testClientID,
				OIDCClientSecret: "0123456789abcdef0123456789abcdef",
				PublicURL:        "http://app.example.com/",
			})
			q, flow := start(t, g, idp)
			assert.NotContains(t, q.Get("scope"), "groups", "Keycloak refuses a scope it doesn't know")

			w := callback(g, "code="+testCode+"&state="+q.Get("state"), flow)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			assert.True(t, readSession(t, g, findCookie(w, "app_session")).SignedIn)
		})
	}
}

func TestOIDCProviderComesUpLater(t *testing.T) {
	t.Parallel()
	idp := newProvider(t)
	idp.down.Store(true)
	g := oidcGuard(t, idp)

	w := do(g.mux, httptest.NewRequest(http.MethodGet, sessionPath+"/oidc", nil))
	assert.Equal(t, http.StatusBadGateway, w.Code)

	idp.down.Store(false)
	start(t, g, idp)
}

func TestOIDCIssuerMismatch(t *testing.T) {
	t.Parallel()
	idp := newProvider(t)
	g := newGuard(t, Config{
		OIDCIssuer: idp.srv.URL + "/", OIDCClientID: testClientID, OIDCClientSecret: "0123456789abcdef",
		OIDCGroup: "admins", PublicURL: "http://app.example.com",
	})
	w := do(g.mux, httptest.NewRequest(http.MethodGet, sessionPath+"/oidc", nil))
	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Contains(t, w.Body.String(), "set up wrong", "the provider answered, so it isn't only about reaching it")
}

func TestOIDCDiscoveryDoesNotQueue(t *testing.T) {
	t.Parallel()
	const signIns = 3
	var waiting atomic.Int32
	all := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer waiting.Add(-1)
		if waiting.Add(1) == signIns {
			close(all)
		}
		select {
		case <-all:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	g := oidcGuard(t, &fakeProvider{srv: srv})

	var wg sync.WaitGroup
	for range signIns {
		wg.Go(func() { do(g.mux, httptest.NewRequest(http.MethodGet, sessionPath+"/oidc", nil)) })
	}
	wg.Wait()
	select {
	case <-all:
	default:
		assert.Fail(t, "the sign ins went to the provider one at a time")
	}
}

func TestOIDCCookieKeyFollowsSecret(t *testing.T) {
	t.Parallel()
	idp := newProvider(t)
	g := oidcGuard(t, idp)
	value := g.sign(time.Now().Add(time.Hour).Unix())

	same := oidcGuard(t, idp)
	assert.True(t, same.signedIn(value), "a restart keeps sessions")

	other := newGuard(t, Config{
		OIDCIssuer: idp.srv.URL, OIDCClientID: testClientID, OIDCClientSecret: "another-secret-another-secret",
		OIDCGroup: "admins", PublicURL: "http://app.example.com",
	})
	assert.False(t, other.signedIn(value), "a new secret ends sessions")
}
