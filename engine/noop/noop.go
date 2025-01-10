package noop

import (
	"context"

	"github.com/tx7do/kratos-authn/engine"
)

type Authenticator struct{}

var _ engine.Authenticator = (*Authenticator)(nil)

func (n Authenticator) Authenticate(_ context.Context, _ engine.ContextType) (*engine.AuthClaims, error) {
	return &engine.AuthClaims{}, nil
}

func (n Authenticator) AuthenticateToken(_ string) (*engine.AuthClaims, error) {
	return &engine.AuthClaims{}, nil
}

func (n Authenticator) CreateIdentityWithContext(ctx context.Context, _ engine.ContextType, _ engine.AuthClaims) (context.Context, error) {
	return ctx, nil
}

func (n Authenticator) CreateIdentity(_ engine.AuthClaims) (string, error) {
	return "", nil
}

func (n Authenticator) Close() {}
