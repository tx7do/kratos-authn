package engine

import (
	"context"
)

type Authenticator interface {
	// Authenticate returns a nil error and the AuthClaims info (if available).
	// if the subject is authenticated or a non-nil error with an appropriate error cause otherwise.
	Authenticate(requestContext context.Context) (*AuthClaims, error)

	// CreateIdentity inject user claims into context.
	CreateIdentity(requestContext context.Context, claims AuthClaims) (string, error)

	// Close Cleans up the authenticator.
	Close()
}
