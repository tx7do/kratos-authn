package jwt

import "github.com/golang-jwt/jwt/v4"

type Options struct {
	signingMethod jwt.SigningMethod
	keyFunc       jwt.Keyfunc
}

type Option func(d *Options)

// WithSigningMethod set signing method
func WithSigningMethod(alg string) Option {
	return func(o *Options) {
		o.signingMethod = jwt.GetSigningMethod(alg)
	}
}

// WithKey set key
func WithKey(key []byte) Option {
	return func(o *Options) {
		o.keyFunc = func(token *jwt.Token) (interface{}, error) {
			return key, nil
		}
	}
}
