// Package oauth2 implements an [engine.Authenticator] that validates
// access tokens using the OAuth2 Token Introspection endpoint (RFC 7662).
//
// The token is transmitted as a Bearer token:
//
//	Authorization: Bearer <access-token>
//
// On AuthenticateToken, the authenticator sends a POST request to the
// introspection endpoint. If the response indicates the token is active,
// the claims from the response (subject, username, scope, etc.) are returned.
package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tx7do/kratos-authn/engine"
)

// introspectionResponse is a subset of RFC 7662 Section 2.2.
type introspectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       any    `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	// Remaining fields are captured for extra claims.
	Extra map[string]json.RawMessage `json:"-"`
}

// Authenticator validates tokens via OAuth2 Token Introspection.
type Authenticator struct {
	options *Options
}

var _ engine.Authenticator = (*Authenticator)(nil)

// NewAuthenticator creates an OAuth2 introspection authenticator.
// Returns an error if the introspection URL is not set.
func NewAuthenticator(opts ...Option) (engine.Authenticator, error) {
	o := &Options{}
	for _, opt := range opts {
		opt(o)
	}
	if o.introspectURL == "" {
		return nil, errors.New("introspection URL is required")
	}
	return &Authenticator{options: o}, nil
}

// Authenticate extracts the Bearer token from the incoming metadata and
// introspects it.
func (a *Authenticator) Authenticate(ctx context.Context, contextType engine.ContextType) (*engine.AuthClaims, error) {
	tokenString, err := engine.AuthFromMD(ctx, engine.BearerWord, contextType)
	if err != nil {
		return nil, engine.ErrMissingBearerToken
	}
	return a.AuthenticateToken(tokenString)
}

// AuthenticateToken sends the token to the introspection endpoint and
// returns the claims if the token is active.
func (a *Authenticator) AuthenticateToken(token string) (*engine.AuthClaims, error) {
	resp, err := a.introspect(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", engine.ErrInvalidToken, err)
	}

	if !resp.Active {
		return nil, engine.ErrUnauthenticated
	}

	return a.responseToClaims(resp), nil
}

// CreateIdentityWithContext injects the token into the outgoing metadata.
// For OAuth2 introspection, the identity is always an external token,
// so this simply passes the subject as a Bearer token.
func (a *Authenticator) CreateIdentityWithContext(ctx context.Context, contextType engine.ContextType, claims engine.AuthClaims) (context.Context, error) {
	token, err := a.CreateIdentity(claims)
	if err != nil {
		return ctx, err
	}
	if token == "" {
		return ctx, nil
	}
	ctx = engine.MDWithAuth(ctx, engine.BearerWord, token, contextType)
	return ctx, nil
}

// CreateIdentity returns the subject from claims (no-op for introspection).
func (a *Authenticator) CreateIdentity(claims engine.AuthClaims) (string, error) {
	sub, _ := claims.GetSubject()
	return sub, nil
}

func (a *Authenticator) Close() {}

// introspect sends a POST request to the RFC 7662 endpoint.
func (a *Authenticator) introspect(token string) (*introspectionResponse, error) {
	form := url.Values{}
	form.Set("token", token)

	req, err := http.NewRequest(http.MethodPost, a.options.introspectURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if a.options.clientID != "" || a.options.clientSecret != "" {
		req.SetBasicAuth(a.options.clientID, a.options.clientSecret)
	}

	resp, err := a.options.getHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("introspection failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Parse into a map first, then selectively extract fields.
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to decode introspection response: %w", err)
	}

	result := &introspectionResponse{Extra: make(map[string]json.RawMessage)}

	// active (required)
	if v, ok := raw["active"]; ok {
		_ = json.Unmarshal(v, &result.Active)
	}

	// standard fields
	for key, dest := range map[string]any{
		"scope":      &result.Scope,
		"client_id":  &result.ClientID,
		"username":   &result.Username,
		"token_type": &result.TokenType,
		"sub":        &result.Sub,
		"iss":        &result.Iss,
	} {
		if v, ok := raw[key]; ok {
			_ = json.Unmarshal(v, dest)
		}
	}

	if v, ok := raw["exp"]; ok {
		_ = json.Unmarshal(v, &result.Exp)
	}
	if v, ok := raw["iat"]; ok {
		_ = json.Unmarshal(v, &result.Iat)
	}
	if v, ok := raw["aud"]; ok {
		result.Aud = v
	}

	// extra claims
	for _, key := range a.options.extraClaimsKeys {
		if v, ok := raw[key]; ok {
			result.Extra[key] = v
		}
	}

	return result, nil
}

func (a *Authenticator) responseToClaims(r *introspectionResponse) *engine.AuthClaims {
	claims := engine.AuthClaims{}

	if r.Sub != "" {
		claims[engine.ClaimFieldSubject] = r.Sub
	}
	if r.Username != "" {
		claims["username"] = r.Username
	}
	if r.Iss != "" {
		claims[engine.ClaimFieldIssuer] = r.Iss
	}
	if r.Scope != "" {
		claims[engine.ClaimFieldScope] = strings.Fields(r.Scope)
	}
	if r.ClientID != "" {
		claims["client_id"] = r.ClientID
	}
	if r.Exp > 0 {
		claims[engine.ClaimFieldExpirationTime] = float64(r.Exp)
	}
	if r.Iat > 0 {
		claims[engine.ClaimFieldIssuedAt] = float64(r.Iat)
	}
	if r.Aud != nil {
		claims[engine.ClaimFieldAudience] = r.Aud
	}

	// extra claims
	for key, raw := range r.Extra {
		var val any
		if err := json.Unmarshal(raw, &val); err == nil {
			claims[key] = val
		}
	}

	return &claims
}
