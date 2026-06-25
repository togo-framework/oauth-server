# oauth-server — usage

## Configure
`OAUTH_SECRET` (HS256 signing secret) and `OAUTH_ISSUER` (issuer URL).

## Register a client
```go
srv, _ := oauthserver.FromKernel(k)
client, secret := srv.RegisterClient("My App",
    []string{"https://app/callback"}, []string{"openid","profile"},
    []string{"authorization_code","refresh_token"}, true /*confidential*/)
// `secret` is returned ONCE for confidential clients.
```

## Authorization code + PKCE
1. Client redirects the user to `GET /oauth/authorize?response_type=code&client_id=…&redirect_uri=…&scope=…&code_challenge=…&code_challenge_method=S256` (the user must be authenticated — `X-User-Id`/session). The server redirects back with `?code=`.
2. Exchange at `POST /oauth/token` (`grant_type=authorization_code`, `code`, `code_verifier`, `redirect_uri`, client auth).

Go API equivalent:
```go
code, _ := srv.IssueCode(client.ID, userID, "openid", redirectURI, challenge, "S256")
tokens, _ := srv.ExchangeCode(code, verifier, redirectURI, client.ID, secret)
```

## Other grants
```go
srv.ClientCredentials(clientID, clientSecret, "api")
srv.RefreshExchange(refreshToken, clientID, clientSecret) // rotates the refresh token
```

## Verify / revoke
```go
info := srv.Introspect(accessToken) // {Active, Sub, Scope, ClientID, Exp, TokenType}
srv.Revoke(token)                   // access (by jti) or refresh
```
REST: `POST /oauth/introspect`, `POST /oauth/revoke`, `GET /oauth/userinfo` (Bearer), discovery at `/.well-known/openid-configuration`, JWKS at `/.well-known/jwks.json`.

## Notes
- Authorization codes are single-use + short-lived (10 min); refresh tokens rotate on use.
- HS256 (symmetric) — resource servers verify via introspection or the shared secret.
