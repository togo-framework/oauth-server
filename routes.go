package oauthserver

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
)

func (s *Server) mountRoutes(r chi.Router) {
	r.Get("/.well-known/openid-configuration", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, 200, s.discovery())
	})
	r.Get("/.well-known/jwks.json", func(w http.ResponseWriter, req *http.Request) {
		// Access tokens are HS256 (symmetric) — verify via /oauth/introspect.
		writeJSON(w, 200, map[string]any{"keys": []any{}})
	})

	r.Route("/oauth", func(r chi.Router) {
		// Authorization endpoint. Assumes an authenticated resource owner
		// (X-User-Id header / upstream session); issues a code + redirects.
		r.Get("/authorize", func(w http.ResponseWriter, req *http.Request) {
			q := req.URL.Query()
			if q.Get("response_type") != "code" {
				writeJSON(w, 400, map[string]string{"error": "unsupported_response_type"})
				return
			}
			user := req.Header.Get("X-User-Id")
			if user == "" {
				writeJSON(w, 401, map[string]string{"error": "login_required"})
				return
			}
			redirect := q.Get("redirect_uri")
			code, err := s.IssueCode(q.Get("client_id"), user, q.Get("scope"), redirect, q.Get("code_challenge"), q.Get("code_challenge_method"))
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": "invalid_request", "error_description": err.Error()})
				return
			}
			loc, _ := url.Parse(redirect)
			rq := loc.Query()
			rq.Set("code", code)
			if st := q.Get("state"); st != "" {
				rq.Set("state", st)
			}
			loc.RawQuery = rq.Encode()
			http.Redirect(w, req, loc.String(), http.StatusFound)
		})

		// Token endpoint.
		r.Post("/token", func(w http.ResponseWriter, req *http.Request) {
			_ = req.ParseForm()
			cid, csec := clientAuth(req)
			var tok *Tokens
			var err error
			switch req.PostFormValue("grant_type") {
			case "authorization_code":
				tok, err = s.ExchangeCode(req.PostFormValue("code"), req.PostFormValue("code_verifier"), req.PostFormValue("redirect_uri"), cid, csec)
			case "client_credentials":
				tok, err = s.ClientCredentials(cid, csec, req.PostFormValue("scope"))
			case "refresh_token":
				tok, err = s.RefreshExchange(req.PostFormValue("refresh_token"), cid, csec)
			default:
				writeJSON(w, 400, map[string]string{"error": "unsupported_grant_type"})
				return
			}
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": "invalid_grant", "error_description": err.Error()})
				return
			}
			writeJSON(w, 200, tok)
		})

		r.Post("/introspect", func(w http.ResponseWriter, req *http.Request) {
			_ = req.ParseForm()
			writeJSON(w, 200, s.Introspect(req.PostFormValue("token")))
		})
		r.Post("/revoke", func(w http.ResponseWriter, req *http.Request) {
			_ = req.ParseForm()
			s.Revoke(req.PostFormValue("token"))
			w.WriteHeader(http.StatusOK)
		})
		r.Get("/userinfo", func(w http.ResponseWriter, req *http.Request) {
			tok := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
			in := s.Introspect(tok)
			if !in.Active {
				writeJSON(w, 401, map[string]string{"error": "invalid_token"})
				return
			}
			writeJSON(w, 200, map[string]any{"sub": in.Sub, "scope": in.Scope, "client_id": in.ClientID})
		})
	})

	// Minimal admin: register a client.
	r.Post("/api/oauth/clients", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Name         string   `json:"name"`
			RedirectURIs []string `json:"redirect_uris"`
			Scopes       []string `json:"scopes"`
			Grants       []string `json:"grants"`
			Confidential bool     `json:"confidential"`
		}
		_ = json.NewDecoder(req.Body).Decode(&in)
		c, secret := s.RegisterClient(in.Name, in.RedirectURIs, in.Scopes, in.Grants, in.Confidential)
		writeJSON(w, 201, map[string]any{"client": c, "client_secret": secret})
	})
}

// clientAuth extracts client_id/secret from Basic auth or the form body.
func clientAuth(req *http.Request) (string, string) {
	if id, secret, ok := req.BasicAuth(); ok {
		return id, secret
	}
	return req.PostFormValue("client_id"), req.PostFormValue("client_secret")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
