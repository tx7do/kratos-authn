// Package apikey implements an [engine.Authenticator] that validates
// opaque API keys.
//
// Keys are transmitted as Bearer tokens:
//
//	Authorization: Bearer <api-key>
//
// Keys can be validated against a static set (WithKeys), a static set with
// per-key claims (WithKeyClaims), or a custom callback (WithValidator)
// for verifying against an external source.
package apikey

import (
	"context"

	"github.com/tx7do/kratos-authn/engine"
)

// Authenticator validates API keys.
type Authenticator struct {
	options *Options
}

var _ engine.Authenticator = (*Authenticator)(nil)

// NewAuthenticator creates an API-Key authenticator from the given options.
func NewAuthenticator(opts ...Option) (engine.Authenticator, error) {
	auth := &Authenticator{options: &Options{}}
	for _, o := range opts {
		o(auth.options)
	}
	return auth, nil
}

// Authenticate extracts the API key from the incoming metadata and validates it.
func (a *Authenticator) Authenticate(ctx context.Context, contextType engine.ContextType) (*engine.AuthClaims, error) {
	tokenString, err := engine.AuthFromMD(ctx, engine.BearerWord, contextType)
	if err != nil {
		return nil, engine.ErrMissingBearerToken
	}
	return a.AuthenticateToken(tokenString)
}

// AuthenticateToken validates the API key and returns the associated claims.
func (a *Authenticator) AuthenticateToken(token string) (*engine.AuthClaims, error) {
	// Validator takes precedence.
	if a.options.validator != nil {
		claims, valid := a.options.validator(token)
		if !valid {
			return nil, engine.ErrUnauthenticated
		}
		c := engine.AuthClaims(claims)
		return &c, nil
	}

	// Static key set.
	if a.options.keys == nil {
		return nil, engine.ErrUnauthenticated
	}

	if _, ok := a.options.keys[token]; !ok {
		return nil, engine.ErrUnauthenticated
	}

	// Return per-key claims if available, otherwise return empty claims.
	if c, ok := a.options.claims[token]; ok {
		claims := engine.AuthClaims(c)
		return &claims, nil
	}

	return &engine.AuthClaims{}, nil
}

// CreateIdentityWithContext injects the API key into the outgoing metadata.
func (a *Authenticator) CreateIdentityWithContext(ctx context.Context, contextType engine.ContextType, claims engine.AuthClaims) (context.Context, error) {
	token, err := a.CreateIdentity(claims)
	if err != nil {
		return ctx, err
	}
	ctx = engine.MDWithAuth(ctx, engine.BearerWord, token, contextType)
	return ctx, nil
}

// CreateIdentity returns the subject from claims as the API key.
func (a *Authenticator) CreateIdentity(claims engine.AuthClaims) (string, error) {
	sub, _ := claims.GetSubject()
	return sub, nil
}

func (a *Authenticator) Close() {}
