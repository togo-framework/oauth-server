<div align="center">
  <img src=".github/assets/togo-mark.svg" alt="togo" height="64" />
  <h1>togo-framework/oauth-server</h1>
  <p>
    <a href="https://to-go.dev/marketplace"><img src="https://img.shields.io/badge/marketplace-to--go.dev-1FC7DC" alt="marketplace" /></a>
    <a href="https://pkg.go.dev/github.com/togo-framework/oauth-server"><img src="https://pkg.go.dev/badge/github.com/togo-framework/oauth-server.svg" alt="pkg.go.dev" /></a>
    <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT" />
  </p>
  <p><strong>OAuth2 / OIDC authorization server for <a href="https://to-go.dev">togo</a> — be an identity provider, not just a consumer.</strong></p>
</div>

## Install

```bash
togo install togo-framework/oauth-server
```

The togo answer to **Laravel Passport / Doorkeeper / django-oauth-toolkit**: issue OAuth2 tokens to client apps. Where [`auth`](https://to-go.dev/plugins/auth) and `auth-oauth` let togo *consume* identity, `oauth-server` lets togo *be* the identity provider.

## Grants & endpoints

- **authorization_code** (with **PKCE** `S256`) · **client_credentials** · **refresh_token** (rotated)
- Access tokens are signed **JWT (HS256)**; refresh tokens are opaque + single-use
- `GET /oauth/authorize` · `POST /oauth/token` · `POST /oauth/introspect` · `POST /oauth/revoke` · `GET /oauth/userinfo`
- `GET /.well-known/openid-configuration` · `GET /.well-known/jwks.json`
- `POST /api/oauth/clients` (register a client)

## Configuration

| Env | Description |
|---|---|
| `OAUTH_SECRET` | HS256 signing secret for access tokens (set in production) |
| `OAUTH_ISSUER` | issuer URL (e.g. `https://id.example.com`) |

## Usage

```go
srv, _ := oauthserver.FromKernel(k)

// Register a client (public/PKCE → no secret; confidential → secret returned once).
client, _ := srv.RegisterClient("My SPA", []string{"https://app.example.com/callback"},
    []string{"openid", "profile"}, []string{"authorization_code", "refresh_token"}, false)

// Authorization code + PKCE (after the user authorizes at /oauth/authorize):
code, _ := srv.IssueCode(client.ID, userID, "openid profile", redirectURI, codeChallenge, "S256")
tokens, _ := srv.ExchangeCode(code, codeVerifier, redirectURI, client.ID, "")
// tokens.AccessToken (JWT) · tokens.RefreshToken

// Verify a token (resource server):
info := srv.Introspect(tokens.AccessToken)   // {Active, Sub, Scope, ClientID, Exp}
srv.Revoke(tokens.AccessToken)
```

### Other grants

```go
srv.ClientCredentials(clientID, clientSecret, "api")   // machine-to-machine
srv.RefreshExchange(refreshToken, clientID, secret)    // rotate
```

> Tokens are HS256 (symmetric), so resource servers verify via `/oauth/introspect` (or the shared secret). The JWKS endpoint returns an empty key set; RS256 with published keys is a planned option.

---

<div align="center">
  <h3>Premium sponsors</h3>
  <p>
    <a href="https://id8media.com"><strong>ID8 Media</strong></a> &nbsp;·&nbsp;
    <a href="https://one-studio.co"><strong>One Studio</strong></a>
  </p>
  <p><sub>Support togo — <a href="https://github.com/sponsors/fadymondy">become a sponsor</a>.</sub></p>
</div>
