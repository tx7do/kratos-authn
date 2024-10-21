package jwt

import (
	jwtV5 "github.com/golang-jwt/jwt/v5"
)

type Options struct {
	signingMethod jwtV5.SigningMethod
	keyFunc       jwtV5.Keyfunc
}

type Option func(d *Options)

// WithSigningMethod set signing method
func WithSigningMethod(alg string) Option {
	return func(o *Options) {
		o.signingMethod = jwtV5.GetSigningMethod(alg)
	}
}

// WithKey set key
func WithKey(key []byte) Option {
	return func(o *Options) {
		o.keyFunc = func(token *jwtV5.Token) (interface{}, error) {
			return key, nil
		}
	}
}
