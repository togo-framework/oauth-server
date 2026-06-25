---
name: oauth-server
description: Turn a togo app into an OAuth2/OIDC identity provider with oauth-server — register clients, run authorization_code+PKCE / client_credentials / refresh_token grants, introspect & revoke tokens, expose discovery & JWKS.
---

# togo oauth-server

Use this skill to make a togo app issue OAuth2 tokens (be an IdP).

## Register a client
```go
srv, _ := oauthserver.FromKernel(k)
client, secret := srv.RegisterClient(name, redirectURIs, scopes, grants, confidential)
```
Public/SPA clients → `confidential=false` + PKCE. Confidential/server clients → `true` (store the returned secret).

## Authorization code + PKCE
- Redirect to `/oauth/authorize?response_type=code&client_id=…&redirect_uri=…&code_challenge=…&code_challenge_method=S256` (user must be logged in).
- Exchange at `POST /oauth/token` (`grant_type=authorization_code`, `code`, `code_verifier`, `redirect_uri`).
Go: `srv.IssueCode(...)` then `srv.ExchangeCode(code, verifier, redirectURI, clientID, secret)`.

## Other grants
`srv.ClientCredentials(id, secret, scope)` · `srv.RefreshExchange(refresh, id, secret)`.

## Verify / revoke
`srv.Introspect(token)` → `{Active, Sub, Scope, …}`; `srv.Revoke(token)`. REST: `/oauth/introspect`, `/oauth/revoke`, `/oauth/userinfo`. Config: `OAUTH_SECRET`, `OAUTH_ISSUER`.

## Notes
- Always require PKCE for public clients; rotate refresh tokens (done automatically).
- HS256 tokens — resource servers verify via introspection.
