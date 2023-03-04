package engine

import (
	"context"
)

type ContextType int

const (
	ContextTypeGrpc = iota
	ContextTypeKratosMetaData
)

// Authenticator interface
type Authenticator interface {
	// Authenticate returns a nil error and the AuthClaims info (if available).
	// if the subject is authenticated or a non-nil error with an appropriate error cause otherwise.
	Authenticate(requestContext context.Context, contextType ContextType) (*AuthClaims, error)

	// AuthenticateToken returns a nil error and the AuthClaims info (if available).
	AuthenticateToken(token string) (*AuthClaims, error)

	// CreateIdentity inject user claims into context.
	CreateIdentity(requestContext context.Context, contextType ContextType, claims AuthClaims) (string, error)

	// Close Cleans up the authenticator.
	Close()
}
