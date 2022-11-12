package authn

import (
	"context"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"

	"github.com/tx7do/kratos-authn/engine"
	"github.com/tx7do/kratos-authn/engine/utils"
)

// Server is a server authenticator middleware.
func Server(authenticator engine.Authenticator) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			claims, err := authenticator.Authenticate(ctx)
			if err != nil {
				return nil, err
			}

			ctx = engine.ContextWithAuthClaims(ctx, claims)

			return handler(ctx, req)
		}
	}
}

// Client is a client authenticator middleware.
func Client(authenticator engine.Authenticator, opts ...Option) middleware.Middleware {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	token, err := authenticator.CreateIdentity(context.Background(), o.claims)
	if err != nil {
		log.Errorf("authenticator middleware create token failed: %s", err.Error())
	}

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			ctx = utils.MDWithAuth(ctx, utils.BearerWord, token, false)
			return handler(ctx, req)
		}
	}
}
