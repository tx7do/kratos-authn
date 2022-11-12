package authn

import (
	"github.com/tx7do/kratos-authn/engine"
)

type Option func(*options)

type options struct {
	claims engine.AuthClaims
}

func WithAuthClaims(claims engine.AuthClaims) Option {
	return func(o *options) {
		o.claims = claims
	}
}
