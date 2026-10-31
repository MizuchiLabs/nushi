# nushi

Sign in for small apps that have one owner instead of users. Password, OIDC, or
nothing on loopback. Plus API tokens for scripts. No database, no user table.

```
go get github.com/mizuchilabs/nushi
```

## Modes

| Mode       | Who gets in                                | Answers on    | Session  |
| ---------- | ------------------------------------------ | ------------- | -------- |
| `none`     | this machine, local host names only        | loopback only |          |
| `password` | whoever knows the password                 | anywhere      | 30 days  |
| `oidc`     | whoever your OIDC provider lets through    | anywhere      | 24 hours |

The mode comes from `<APP>_AUTH`. Left empty, it follows what is set: a
password means `password`, an issuer means `oidc`, neither means `none`.
A mode that misses a setting fails at startup.

Mode `none` is for local dev, or a proxy on the same machine, which can bring
in the local network. It can't work in a container behind Traefik. Traefik
comes in on the container's network address, not loopback, so every request
gets a 403. Use `password` or `oidc` there.

API tokens work in `password` and `oidc` mode, as `Authorization: Bearer <token>`.

The OIDC session is short so that removing someone at the provider locks them
out within a day. When it runs out the app sends you through the provider
again, which is instant while your session there lasts.

## Config

The env vars carry the app's prefix, `MYAPP_` for an app called `myapp`.

| Var                        | Mode       |                                                                         |
| -------------------------- | ---------- | ----------------------------------------------------------------------- |
| `<APP>_AUTH`               | all        | `none`, `password` or `oidc`, optional                                  |
| `<APP>_PASSWORD`           | `password` | at least 12 characters                                                  |
| `<APP>_API_TOKEN`          | not `none` | at least 32 characters each, comma separated to roll to a new one       |
| `<APP>_OIDC_ISSUER`        | `oidc`     | `https://id.example.com`                                                |
| `<APP>_OIDC_CLIENT_ID`     | `oidc`     |                                                                         |
| `<APP>_OIDC_CLIENT_SECRET` | `oidc`     | at least 16 characters, it also keys the cookie                         |
| `<APP>_OIDC_GROUP`         | `oidc`     | optional, only this group gets in, see [Who gets in](#who-gets-in)      |
| `<APP>_PUBLIC_URL`         | `oidc`     | the site root where browsers reach the app, no path                     |
| `<APP>_TRUSTED_PROXIES`    | not `none` | proxy IPs or ranges, see [Behind a proxy](#behind-a-proxy)              |
| `<APP>_TRUSTED_HOSTS`      | `none`     | extra host names or IP ranges the app answers to, no ports              |

## Behind a proxy

Traefik on a docker network works without any setup. nushi trusts
`X-Forwarded-For` and `X-Forwarded-Proto` from any proxy on a private address,
so the sign in limit counts each real client and the cookie gets `Secure`.

Until you pin the proxy, the app logs a warning once. Pin it with the subnet
of the proxy's docker network, as `docker network inspect <network>` shows:

```yaml
environment:
  MYAPP_TRUSTED_PROXIES: 172.18.0.0/16
```

Pinning stops other devices on your network from faking their address. The
list replaces the private default, so it has to hold every proxy in the chain.
If a private address that is not pinned sends forwarded headers, say after the
proxy moved, the app logs that once too.

- Something in front of Traefik, such as Cloudflare, has to be trusted by
  Traefik (`forwardedHeaders.trustedIPs`). Its ranges go in this list next to
  the docker subnet, not instead of it.
- Don't rewrite `RemoteAddr` before the guard, for example with chi's
  `middleware.RealIP`. That hands nushi an address anyone can fake.

## OIDC with PocketID

1. Add an OIDC client in PocketID with the callback URL
   `<PUBLIC_URL>/api/session/oidc/callback`.
2. On the client's Access tab, pick the groups that may sign in. A new client
   lets nobody in.
3. Set the env vars:

```yaml
environment:
  MYAPP_OIDC_ISSUER: https://id.example.com
  MYAPP_OIDC_CLIENT_ID: 7f3c...
  MYAPP_OIDC_CLIENT_SECRET: ${MYAPP_OIDC_CLIENT_SECRET}
  MYAPP_PUBLIC_URL: https://myapp.example.com
```

The app has to reach the issuer under the same URL the browser uses, the ID
token names it. In Docker, put the app on Traefik's network so
`id.example.com` resolves. Don't put forward auth in front of the app, it
signs you in itself.

A sign in that starts on another host, such as `127.0.0.1` with a public URL on
`localhost`, moves to the public URL first and stays there.

A new client secret ends every session, the same as a new password.

## Who gets in

Everyone your provider lets through gets the whole app, nushi has no users to
tell apart. So limit the client at the provider. Most can do that, for example
bindings in Authentik or the project's role check in Zitadel.

Where that isn't simple, as in Keycloak or on a public provider, set
`<APP>_OIDC_GROUP` too. nushi then asks for the `groups` scope and only lets in
that group, from the ID token's `groups` claim or userinfo.

- PocketID, Authentik, Authelia and Dex send the claim as is.
- Keycloak needs a `groups` client scope with a group membership mapper, it
  refuses the sign in without one.
- Kanidm needs `groups` in the scope map, and takes the group as UUID or SPN.
- Zitadel has roles, not groups. It only sends the claim from an Action you
  write.

## Use

```go
guard, err := nushi.FromEnv("myapp") // reads MYAPP_*
if err != nil {
	return err
}

mux := http.NewServeMux()
mux.Handle("/api/", guard.Require(api))
mux.Handle("/", ui) // the sign in page has to load

ln, err := guard.Listen(ctx, addr)
if err != nil {
	return err
}
return http.Serve(ln, guard.Protect(mux))
```

- `Protect` wraps the whole app, once. It serves the routes below and keeps
  other sites out. Without it sign in does not work.
- `Require` goes on whatever needs a sign in. Only your app knows where that
  starts.
- `Listen` is optional. In mode `none` it fails at startup on anything but
  loopback. Without it the app starts and `Protect` answers 403 to everything
  that does not come in on loopback.

`guard.Allowed(r)` answers the same question as `Require` for a framework's
own middleware, mode `none` checks included.

With connect, wrap the handler. An interceptor never sees the `*http.Request`,
so `Allowed` doesn't fit there.

```go
path, handler := thingv1connect.NewThingServiceHandler(svc)
mux.Handle(path, guard.Require(handler))
```

With huma, give it its own mux and wrap that. To check per operation instead,
call `guard.Allowed` from a huma middleware with the request from
`humago.Unwrap(ctx)`.

```go
routes := http.NewServeMux()
api := humago.New(routes, huma.DefaultConfig("myapp", "1.0.0"))
huma.Get(api, "/api/things", listThings)
mux.Handle("/api/", guard.Require(routes))
```

The app name is the env prefix. It also names the cookies and salts the session
key, so two apps on one host stay apart even with the same password. Cookies
ignore the port.

If your settings don't come from env vars, pass them yourself. Error messages
still use the env var names.

```go
guard, err := nushi.New("myapp", nushi.Config{Password: password})
```

Failed sign ins and provider errors go to `slog`'s default logger. The browser
only gets a short reason.

In your tests, `httptest.NewRequest` uses the host `example.com`. Mode `none`
doesn't trust that name, so `Require` answers 401. Set `r.Host = "localhost"`.

## Routes

| Route                            | What it does                                              |
| -------------------------------- | --------------------------------------------------------- |
| `GET /api/session`               | `{"mode":"oidc","signed_in":true,"api_token":true}`         |
| `POST /api/session`              | password mode, body `{"password":"..."}`, sets the cookie |
| `DELETE /api/session`            | signs out                                                 |
| `GET /api/session/oidc`          | oidc mode, send the browser here to sign in               |
| `GET /api/session/oidc/callback` | the provider sends the browser back here                  |

`api_token` is only told to a signed in browser. Errors are
`application/problem+json` with a `detail`.

## Frontend

nushi has no sign in page, that part is yours. Ask `GET /api/session` what to
show.

```js
const session = await (await fetch("/api/session")).json();

if (session.signed_in) {
  showApp();
} else if (session.mode === "password") {
  showPasswordForm();
} else {
  showSignInLink(); // <a href="/api/session/oidc">Sign in</a>
}

async function signIn(password) {
  const res = await fetch("/api/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });
  if (!res.ok) throw new Error((await res.json()).detail);
}

async function signOut() {
  await fetch("/api/session", { method: "DELETE" });
}
```

- The OIDC sign in is a page load, not a `fetch`. The provider sends the
  browser back to `/`.
- Sending the browser there on its own works for a session that ran out, but
  not right after a sign out. It would sign you straight back in, so a link is
  the safe default.
- A 401 from your API means the session ran out. Ask `GET /api/session` again.

## What it guards against

- Password guessing: 5 tries a minute per real client, 30 for all together.
  Your local network has its own 30, so a crowd outside can't lock you out at home.
- A leaked cookie: in password mode the key comes from the password through
  600k PBKDF2 rounds.
- Other sites: cross-origin writes and WebSocket handshakes are refused, the
  UI cannot be framed.
- Mode `none` going public: anything that comes in on an address other than
  loopback is turned away, however the app binds. So is anything a proxy
  brought in from outside the local network, and unknown host names, which also
  stops DNS rebinding.
- OIDC: state, nonce and PKCE on every sign in, the ID token is checked for
  issuer, audience and expiry, and for the group if you set one.

## What it doesn't do

- Sign out only clears the cookie in this browser. The session is not stored
  anywhere, so a stolen cookie works until it runs out, or until you change the
  password or the client secret.
