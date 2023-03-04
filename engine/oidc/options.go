package oidc

import (
	"github.com/golang-jwt/jwt/v4"
)

type Options struct {
	IssuerURL string
	Audience  string

	signingMethod jwt.SigningMethod
}

type Option func(d *Options)

// WithIssuerURL set issuer url
func WithIssuerURL(url string) Option {
	return func(o *Options) {
		o.IssuerURL = url
	}
}

// WithAudience set audience
func WithAudience(audience string) Option {
	return func(o *Options) {
		o.Audience = audience
	}
}

// WithSigningMethod set signing method
func WithSigningMethod(alg string) Option {
	return func(o *Options) {
		o.signingMethod = jwt.GetSigningMethod(alg)
	}
}
