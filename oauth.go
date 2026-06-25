// Package oauthserver turns a togo app into an OAuth2 / OIDC authorization
// server — an identity provider that issues tokens to client apps (the togo
// answer to Laravel Passport / Doorkeeper / django-oauth-toolkit).
//
// Supported grants: authorization_code (with PKCE S256), client_credentials,
// and refresh_token. Access tokens are signed JWTs (HS256); refresh tokens are
// opaque + rotated. Endpoints: /oauth/authorize, /oauth/token, /oauth/introspect,
// /oauth/revoke, /oauth/userinfo, /.well-known/{openid-configuration,jwks.json}.
package oauthserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/togo-framework/togo"
)

// Client is a registered OAuth2 client application.
type Client struct {
	ID           string   `json:"client_id"`
	SecretHash   string   `json:"-"`             // sha256-hex of the secret ("" = public client)
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	Grants       []string `json:"grants"`
}

type authCode struct {
	clientID, userID, scope, redirectURI, challenge, method string
	expiry                                                  time.Time
}

type refreshToken struct {
	clientID, userID, scope string
	expiry                  time.Time
}

// Tokens is the token endpoint response.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Introspection is the RFC 7662 token-introspection response.
type Introspection struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

// Server is the OAuth2 authorization server stored on the kernel.
type Server struct {
	mu         sync.Mutex
	clients    map[string]*Client
	codes      map[string]*authCode
	refresh    map[string]*refreshToken
	revoked    map[string]bool
	secret     []byte
	issuer     string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func init() {
	togo.RegisterProviderFunc("oauth-server", togo.PriorityService, func(k *togo.Kernel) error {
		s := New()
		k.Set("oauth-server", s)
		if k.Router != nil {
			s.mountRoutes(k.Router)
		}
		return nil
	})
}

// New builds a Server from env (OAUTH_SECRET, OAUTH_ISSUER).
func New() *Server {
	secret := os.Getenv("OAUTH_SECRET")
	if secret == "" {
		secret = "dev-oauth-secret-change-me"
	}
	issuer := os.Getenv("OAUTH_ISSUER")
	if issuer == "" {
		issuer = "https://localhost"
	}
	return &Server{
		clients: map[string]*Client{}, codes: map[string]*authCode{},
		refresh: map[string]*refreshToken{}, revoked: map[string]bool{},
		secret: []byte(secret), issuer: issuer,
		accessTTL: time.Hour, refreshTTL: 30 * 24 * time.Hour,
	}
}

// FromKernel returns the OAuth Server registered on the kernel.
func FromKernel(k *togo.Kernel) (*Server, bool) {
	v, ok := k.Get("oauth-server")
	if !ok {
		return nil, false
	}
	s, ok := v.(*Server)
	return s, ok
}

// RegisterClient registers a client; the plaintext secret is returned once for
// confidential clients (empty for public/PKCE clients).
func (s *Server) RegisterClient(name string, redirectURIs, scopes, grants []string, confidential bool) (*Client, string) {
	c := &Client{ID: "cl_" + randStr(20), Name: name, RedirectURIs: redirectURIs, Scopes: scopes, Grants: grants}
	secret := ""
	if confidential {
		secret = randStr(40)
		h := sha256.Sum256([]byte(secret))
		c.SecretHash = hex.EncodeToString(h[:])
	}
	s.mu.Lock()
	s.clients[c.ID] = c
	s.mu.Unlock()
	return c, secret
}

// Client returns a registered client.
func (s *Server) Client(id string) (*Client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	return c, ok
}

// IssueCode issues an authorization code after the resource owner authorizes.
func (s *Server) IssueCode(clientID, userID, scope, redirectURI, challenge, method string) (string, error) {
	s.mu.Lock()
	c := s.clients[clientID]
	s.mu.Unlock()
	if c == nil {
		return "", errors.New("unknown client")
	}
	if !contains(c.RedirectURIs, redirectURI) {
		return "", errors.New("redirect_uri mismatch")
	}
	code := randStr(32)
	s.mu.Lock()
	s.codes[code] = &authCode{clientID: clientID, userID: userID, scope: scope, redirectURI: redirectURI, challenge: challenge, method: method, expiry: time.Now().Add(10 * time.Minute)}
	s.mu.Unlock()
	return code, nil
}

// ExchangeCode runs the authorization_code grant (with PKCE if a challenge was set).
func (s *Server) ExchangeCode(code, verifier, redirectURI, clientID, clientSecret string) (*Tokens, error) {
	s.mu.Lock()
	ac := s.codes[code]
	delete(s.codes, code)
	c := s.clients[clientID]
	s.mu.Unlock()
	if ac == nil || time.Now().After(ac.expiry) {
		return nil, errors.New("invalid_grant: code")
	}
	if ac.clientID != clientID || ac.redirectURI != redirectURI {
		return nil, errors.New("invalid_grant: mismatch")
	}
	if c == nil {
		return nil, errors.New("invalid_client")
	}
	if c.SecretHash != "" && !s.checkSecret(c, clientSecret) {
		return nil, errors.New("invalid_client")
	}
	if ac.challenge != "" && !verifyPKCE(ac.challenge, ac.method, verifier) {
		return nil, errors.New("invalid_grant: pkce")
	}
	return s.issueTokens(c.ID, ac.userID, ac.scope, true)
}

// ClientCredentials runs the client_credentials grant.
func (s *Server) ClientCredentials(clientID, clientSecret, scope string) (*Tokens, error) {
	s.mu.Lock()
	c := s.clients[clientID]
	s.mu.Unlock()
	if c == nil || !s.checkSecret(c, clientSecret) || c.SecretHash == "" {
		return nil, errors.New("invalid_client")
	}
	if !contains(c.Grants, "client_credentials") {
		return nil, errors.New("unauthorized_client")
	}
	return s.issueTokens(c.ID, "", scope, false)
}

// RefreshExchange runs the refresh_token grant (rotating the refresh token).
func (s *Server) RefreshExchange(refreshTok, clientID, clientSecret string) (*Tokens, error) {
	s.mu.Lock()
	rt := s.refresh[refreshTok]
	c := s.clients[clientID]
	s.mu.Unlock()
	if rt == nil || time.Now().After(rt.expiry) || s.isRevoked(refreshTok) {
		return nil, errors.New("invalid_grant: refresh")
	}
	if rt.clientID != clientID {
		return nil, errors.New("invalid_grant")
	}
	if c != nil && c.SecretHash != "" && !s.checkSecret(c, clientSecret) {
		return nil, errors.New("invalid_client")
	}
	s.mu.Lock()
	delete(s.refresh, refreshTok)
	s.mu.Unlock()
	return s.issueTokens(rt.clientID, rt.userID, rt.scope, true)
}

func (s *Server) issueTokens(clientID, userID, scope string, withRefresh bool) (*Tokens, error) {
	jti := randStr(16)
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": s.issuer, "sub": userID, "client_id": clientID, "scope": scope,
		"iat": now.Unix(), "exp": now.Add(s.accessTTL).Unix(), "jti": jti,
	}
	access, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
	if err != nil {
		return nil, err
	}
	out := &Tokens{AccessToken: access, TokenType: "Bearer", ExpiresIn: int(s.accessTTL.Seconds()), Scope: scope}
	if withRefresh {
		rt := randStr(40)
		s.mu.Lock()
		s.refresh[rt] = &refreshToken{clientID: clientID, userID: userID, scope: scope, expiry: now.Add(s.refreshTTL)}
		s.mu.Unlock()
		out.RefreshToken = rt
	}
	return out, nil
}

// Introspect reports whether a token (access JWT or refresh) is active.
func (s *Server) Introspect(token string) Introspection {
	if s.isRevoked(token) {
		return Introspection{Active: false}
	}
	claims := jwt.MapClaims{}
	t, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return s.secret, nil })
	if err == nil && t.Valid {
		if jti := str(claims["jti"]); jti != "" && s.isRevoked(jti) {
			return Introspection{Active: false}
		}
		var exp int64
		if v, ok := claims["exp"].(float64); ok {
			exp = int64(v)
		}
		return Introspection{Active: true, Scope: str(claims["scope"]), ClientID: str(claims["client_id"]), Sub: str(claims["sub"]), Exp: exp, TokenType: "access_token"}
	}
	s.mu.Lock()
	rt := s.refresh[token]
	s.mu.Unlock()
	if rt != nil && time.Now().Before(rt.expiry) {
		return Introspection{Active: true, Scope: rt.scope, ClientID: rt.clientID, Sub: rt.userID, Exp: rt.expiry.Unix(), TokenType: "refresh_token"}
	}
	return Introspection{Active: false}
}

// Revoke invalidates an access (by jti) or refresh token.
func (s *Server) Revoke(token string) {
	s.mu.Lock()
	if _, ok := s.refresh[token]; ok {
		delete(s.refresh, token)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	claims := jwt.MapClaims{}
	if t, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return s.secret, nil }); err == nil && t.Valid {
		if jti := str(claims["jti"]); jti != "" {
			s.mu.Lock()
			s.revoked[jti] = true
			s.mu.Unlock()
			return
		}
	}
	s.mu.Lock()
	s.revoked[token] = true
	s.mu.Unlock()
}

func (s *Server) isRevoked(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked[tok]
}

func (s *Server) checkSecret(c *Client, secret string) bool {
	if c.SecretHash == "" {
		return true
	}
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:]) == c.SecretHash
}

func verifyPKCE(challenge, method, verifier string) bool {
	if verifier == "" {
		return false
	}
	switch method {
	case "S256", "":
		sum := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
	case "plain":
		return verifier == challenge
	}
	return false
}

// discovery returns the OIDC discovery document.
func (s *Server) discovery() map[string]any {
	return map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/oauth/authorize",
		"token_endpoint":                        s.issuer + "/oauth/token",
		"introspection_endpoint":                s.issuer + "/oauth/introspect",
		"revocation_endpoint":                   s.issuer + "/oauth/revoke",
		"userinfo_endpoint":                     s.issuer + "/oauth/userinfo",
		"jwks_uri":                              s.issuer + "/.well-known/jwks.json",
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token"},
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		"id_token_signing_alg_values_supported": []string{"HS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
	}
}

func contains(ss []string, x string) bool {
	for _, s := range ss {
		if s == x {
			return true
		}
	}
	return false
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func randStr(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}
