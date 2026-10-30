package nushi

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	callbackPath = sessionPath + "/oidc/callback"
	flowTTL      = 10 * time.Minute
)

// continuePage lands the browser on the app. A redirect chain that started on
// the provider may not carry the Strict session cookie, a navigation from our
// own page does.
const continuePage = `<!doctype html><meta http-equiv="refresh" content="0;url=/"><a href="/">Continue</a>`

type oidcClient struct {
	issuer   string
	conf     oauth2.Config
	group    string
	client   *http.Client
	provider atomic.Pointer[oidc.Provider]
}

func newOIDC(c Config) *oidcClient {
	return &oidcClient{
		issuer: c.OIDCIssuer,
		group:  c.OIDCGroup,
		client: &http.Client{Timeout: 10 * time.Second},
		conf: oauth2.Config{
			ClientID:     c.OIDCClientID,
			ClientSecret: c.OIDCClientSecret,
			RedirectURL:  strings.TrimSuffix(c.PublicURL, "/") + callbackPath,
			Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeProfile, "groups"},
		},
	}
}

// ready discovers the provider on first use. It may come up after the app,
// so a failure is tried again on the next sign in. No lock around the call, a
// hung provider must not queue every sign in. Two at once just discover twice.
// go-oidc keeps the client from ctx for its key refreshes, never ctx itself.
func (o *oidcClient) ready(ctx context.Context) (*oidc.Provider, oauth2.Config, error) {
	p := o.provider.Load()
	if p == nil {
		var err error
		p, err = oidc.NewProvider(oidc.ClientContext(ctx, o.client), o.issuer)
		if err != nil {
			return nil, oauth2.Config{}, fmt.Errorf("reaching the sign in provider: %w", err)
		}
		o.provider.Store(p)
	}
	conf := o.conf
	conf.Endpoint = p.Endpoint()
	return p, conf, nil
}

func (g *Guard) oidcStart(w http.ResponseWriter, r *http.Request) {
	_, conf, err := g.oidc.ready(r.Context())
	if err != nil {
		fail(w, http.StatusBadGateway, "the sign in provider is not reachable or set up wrong, see the app's log", err)
		return
	}
	state, nonce, verifier := rand.Text(), rand.Text(), oauth2.GenerateVerifier()
	http.SetCookie(w, g.flowCookie(state+"."+nonce+"."+verifier, int(flowTTL.Seconds()), g.secure(r)))
	target := conf.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, target, http.StatusFound)
}

func (g *Guard) oidcCallback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(g.flowName())
	if err != nil {
		fail(w, http.StatusBadRequest, "the sign in took too long or started in another browser", nil)
		return
	}
	state, rest, _ := strings.Cut(c.Value, ".")
	nonce, verifier, _ := strings.Cut(rest, ".")

	// Nothing in the query counts before the state matches, a stray link must not end a sign in either.
	q := r.URL.Query()
	if state == "" || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
		fail(w, http.StatusBadRequest, "the sign in does not match the one this browser started", nil)
		return
	}
	http.SetCookie(w, g.flowCookie("", -1, g.secure(r)))
	if e := q.Get("error"); e != "" {
		fail(w, http.StatusUnauthorized, "the provider said "+cmp.Or(q.Get("error_description"), e), nil)
		return
	}

	p, conf, err := g.oidc.ready(r.Context())
	if err != nil {
		fail(w, http.StatusBadGateway, "the sign in provider is not reachable or set up wrong, see the app's log", err)
		return
	}
	ctx := oidc.ClientContext(r.Context(), g.oidc.client)
	tok, err := conf.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		fail(w, http.StatusBadGateway, "the provider did not take the sign in", err)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := p.Verifier(&oidc.Config{ClientID: conf.ClientID}).Verify(ctx, raw)
	if err != nil {
		fail(w, http.StatusUnauthorized, "the provider's ID token is not valid", err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(nonce)) != 1 {
		fail(w, http.StatusUnauthorized, "the ID token belongs to another sign in", nil)
		return
	}
	var claims struct {
		Groups []string `json:"groups"`
	}
	if err := idt.Claims(&claims); err != nil {
		slog.Warn("reading the groups from the ID token", "err", err)
	}
	// Some providers only tell the groups through userinfo.
	if claims.Groups == nil {
		if info, err := p.UserInfo(ctx, oauth2.StaticTokenSource(tok)); err == nil && info.Subject == idt.Subject {
			_ = info.Claims(&claims)
		}
	}
	if !slices.Contains(claims.Groups, g.oidc.group) {
		slog.Warn("oidc sign in refused, not in the group", "sub", idt.Subject, "group", g.oidc.group)
		fail(w, http.StatusForbidden, "this account is not in the group "+g.oidc.group, nil)
		return
	}

	g.startSession(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(continuePage))
}

// flowCookie holds state, nonce and PKCE verifier while the browser is at
// the provider. Lax, since it has to come back with the provider's redirect.
func (g *Guard) flowCookie(value string, maxAge int, secure bool) *http.Cookie {
	//nolint:gosec // Secure follows the request, plain HTTP on a private network has to work
	return &http.Cookie{
		Name:     g.flowName(),
		Value:    value,
		Path:     sessionPath + "/oidc",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

func (g *Guard) flowName() string {
	return g.name + "_oidc"
}

// fail tells the browser msg. err holds details for the log only.
func fail(w http.ResponseWriter, status int, msg string, err error) {
	if err != nil {
		slog.Warn("oidc sign in failed", "reason", msg, "err", err)
	}
	http.Error(w, "Sign in failed, "+msg+". Go back to the app and try again.", status)
}
