package engine

import (
	"context"
)

type ctxKey string

var (
	authClaimsContextKey = ctxKey("authn-claims")
)

type ScopeSet map[string]bool

// AuthClaims contains claims that are included in OIDC standard claims.
// See https://openid.net/specs/openid-connect-core-1_0.html#IDToken
type AuthClaims struct {
	Subject string

	// Scopes see: https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
	Scopes ScopeSet
}

// ContextWithAuthClaims injects the provided AuthClaims into the parent context.
func ContextWithAuthClaims(parent context.Context, claims *AuthClaims) context.Context {
	return context.WithValue(parent, authClaimsContextKey, claims)
}

// AuthClaimsFromContext extracts the AuthClaims from the provided ctx (if any).
func AuthClaimsFromContext(ctx context.Context) (*AuthClaims, bool) {
	claims, ok := ctx.Value(authClaimsContextKey).(*AuthClaims)
	if !ok {
		return nil, false
	}

	return claims, true
}
