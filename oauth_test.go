package oauthserver

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func pkce(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestAuthorizationCodePKCEHappyPath(t *testing.T) {
	s := New()
	c, _ := s.RegisterClient("web", []string{"https://app/cb"}, []string{"openid"}, []string{"authorization_code"}, false)
	verifier := "a-long-random-code-verifier-string-1234567890"
	code, err := s.IssueCode(c.ID, "user-1", "openid", "https://app/cb", pkce(verifier), "S256")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.ExchangeCode(code, verifier, "https://app/cb", c.ID, "")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" || tok.TokenType != "Bearer" {
		t.Fatalf("bad tokens: %+v", tok)
	}
	in := s.Introspect(tok.AccessToken)
	if !in.Active || in.Sub != "user-1" || in.Scope != "openid" {
		t.Fatalf("introspect: %+v", in)
	}
}

func TestWrongPKCERejected(t *testing.T) {
	s := New()
	c, _ := s.RegisterClient("web", []string{"https://app/cb"}, nil, []string{"authorization_code"}, false)
	code, _ := s.IssueCode(c.ID, "u", "", "https://app/cb", pkce("the-real-verifier"), "S256")
	if _, err := s.ExchangeCode(code, "the-WRONG-verifier", "https://app/cb", c.ID, ""); err == nil {
		t.Fatal("wrong PKCE verifier must be rejected")
	}
}

func TestCodeIsSingleUse(t *testing.T) {
	s := New()
	c, _ := s.RegisterClient("web", []string{"https://app/cb"}, nil, []string{"authorization_code"}, false)
	v := "verifier-xyz"
	code, _ := s.IssueCode(c.ID, "u", "", "https://app/cb", pkce(v), "S256")
	if _, err := s.ExchangeCode(code, v, "https://app/cb", c.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExchangeCode(code, v, "https://app/cb", c.ID, ""); err == nil {
		t.Fatal("authorization code must be single-use")
	}
}

func TestClientCredentials(t *testing.T) {
	s := New()
	c, secret := s.RegisterClient("svc", nil, []string{"api"}, []string{"client_credentials"}, true)
	if secret == "" {
		t.Fatal("confidential client should return a secret")
	}
	tok, err := s.ClientCredentials(c.ID, secret, "api")
	if err != nil {
		t.Fatalf("client_credentials: %v", err)
	}
	if tok.AccessToken == "" || tok.RefreshToken != "" { // no refresh for client_credentials
		t.Fatalf("bad cc tokens: %+v", tok)
	}
	// Wrong secret rejected.
	if _, err := s.ClientCredentials(c.ID, "nope", "api"); err == nil {
		t.Fatal("wrong client secret must be rejected")
	}
}

func TestRefreshRotation(t *testing.T) {
	s := New()
	c, _ := s.RegisterClient("web", []string{"https://app/cb"}, nil, []string{"authorization_code", "refresh_token"}, false)
	v := "verifier"
	code, _ := s.IssueCode(c.ID, "u9", "", "https://app/cb", pkce(v), "S256")
	first, _ := s.ExchangeCode(code, v, "https://app/cb", c.ID, "")

	second, err := s.RefreshExchange(first.RefreshToken, c.ID, "")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("refresh token should rotate")
	}
	// The old refresh token must no longer work.
	if _, err := s.RefreshExchange(first.RefreshToken, c.ID, ""); err == nil {
		t.Fatal("rotated-out refresh token must be invalid")
	}
}

func TestRevokeAndIntrospect(t *testing.T) {
	s := New()
	c, _ := s.RegisterClient("web", []string{"https://app/cb"}, nil, []string{"authorization_code"}, false)
	v := "verifier"
	code, _ := s.IssueCode(c.ID, "u", "", "https://app/cb", pkce(v), "S256")
	tok, _ := s.ExchangeCode(code, v, "https://app/cb", c.ID, "")

	if !s.Introspect(tok.AccessToken).Active {
		t.Fatal("token should be active before revoke")
	}
	s.Revoke(tok.AccessToken)
	if s.Introspect(tok.AccessToken).Active {
		t.Fatal("token should be inactive after revoke")
	}
	// Unknown / garbage token is inactive, not a crash.
	if s.Introspect("garbage.token.value").Active {
		t.Fatal("garbage token must be inactive")
	}
}

func TestDiscoveryDocShape(t *testing.T) {
	s := New()
	d := s.discovery()
	for _, k := range []string{"issuer", "authorization_endpoint", "token_endpoint", "introspection_endpoint", "jwks_uri", "grant_types_supported", "code_challenge_methods_supported"} {
		if _, ok := d[k]; !ok {
			t.Errorf("discovery missing %q", k)
		}
	}
}

func TestRedirectURIMismatch(t *testing.T) {
	s := New()
	c, _ := s.RegisterClient("web", []string{"https://app/cb"}, nil, []string{"authorization_code"}, false)
	if _, err := s.IssueCode(c.ID, "u", "", "https://evil/cb", "", ""); err == nil {
		t.Fatal("redirect_uri not in the client's allowlist must be rejected")
	}
}
