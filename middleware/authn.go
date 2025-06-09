package middleware

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"

	"github.com/tx7do/kratos-authn/engine"
)

// Server is server authenticator middleware.
func Server(authenticator engine.Authenticator, opts ...Option) middleware.Middleware {
	o := &options{
		log: log.NewHelper(log.With(log.DefaultLogger, "module", "authn.middleware")),
	}
	for _, opt := range opts {
		opt(o)
	}

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			claims, err := authenticator.Authenticate(ctx, engine.ContextTypeKratosMetaData)
			if err != nil {
				o.log.Errorf("authenticator middleware authenticate failed: %s", err.Error())
				return nil, ErrUnauthorized
			}

			ctx = engine.ContextWithAuthClaims(ctx, claims)

			return handler(ctx, req)
		}
	}
}

// Client is client authenticator middleware.
func Client(authenticator engine.Authenticator, opts ...Option) middleware.Middleware {
	o := &options{
		log: log.NewHelper(log.With(log.DefaultLogger, "module", "authn.middleware")),
	}
	for _, opt := range opts {
		opt(o)
	}

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			var err error
			if ctx, err = authenticator.CreateIdentityWithContext(ctx, engine.ContextTypeKratosMetaData, o.claims); err != nil {
				o.log.Errorf("authenticator middleware create token failed: %s", err.Error())
			}
			return handler(ctx, req)
		}
	}
}
