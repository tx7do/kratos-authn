package jwt

import (
	jwtV5 "github.com/golang-jwt/jwt/v5"
)

type Options struct {
	signingMethod jwtV5.SigningMethod
	signingKey    interface{}   // key for signing tokens (RSA private key for RS256)
	keyFunc       jwtV5.Keyfunc // function to retrieve key for verifying tokens (RSA public key for RS256)
}

type Option func(d *Options)

// WithSigningMethod sets the signing method (e.g. "HS256", "RS256").
func WithSigningMethod(alg string) Option {
	return func(o *Options) {
		o.signingMethod = jwtV5.GetSigningMethod(alg)
	}
}

// WithKey sets a single key used for both signing and verification.
// Suitable for symmetric algorithms (e.g. HS256).
func WithKey(key interface{}) Option {
	return func(o *Options) {
		o.signingKey = key
		o.keyFunc = func(token *jwtV5.Token) (interface{}, error) {
			return key, nil
		}
	}
}

// WithSigningKey sets the key for signing tokens.
// Supported types:
//   - HMAC (HS256/HS384/HS512): []byte
//   - RSA (RS256/RS384/RS512, PS256/PS384/PS512): *rsa.PrivateKey
//   - ECDSA (ES256/ES384/ES512): *ecdsa.PrivateKey
//   - EdDSA: ed25519.PrivateKey
func WithSigningKey(key interface{}) Option {
	return func(o *Options) {
		o.signingKey = key
	}
}

// WithVerificationKey sets the key for verifying tokens.
// Supported types:
//   - HMAC (HS256/HS384/HS512): []byte
//   - RSA (RS256/RS384/RS512, PS256/PS384/PS512): *rsa.PublicKey
//   - ECDSA (ES256/ES384/ES512): *ecdsa.PublicKey
//   - EdDSA: ed25519.PublicKey
func WithVerificationKey(key interface{}) Option {
	return func(o *Options) {
		o.keyFunc = func(token *jwtV5.Token) (interface{}, error) {
			return key, nil
		}
	}
}

// WithPrivateKeyFromPEM parses a PEM-encoded RSA private key and sets it for signing.
// Suitable for RS256/RS384/RS512 and PS256/PS384/PS512.
func WithPrivateKeyFromPEM(pemBytes []byte) Option {
	return func(o *Options) {
		key, err := jwtV5.ParseRSAPrivateKeyFromPEM(pemBytes)
		if err != nil {
			return
		}
		o.signingKey = key
	}
}

// WithPublicKeyFromPEM parses a PEM-encoded RSA public key and sets it for verification.
// Suitable for RS256/RS384/RS512 and PS256/PS384/PS512.
func WithPublicKeyFromPEM(pemBytes []byte) Option {
	return func(o *Options) {
		key, err := jwtV5.ParseRSAPublicKeyFromPEM(pemBytes)
		if err != nil {
			return
		}
		o.keyFunc = func(token *jwtV5.Token) (interface{}, error) {
			return key, nil
		}
	}
}

// WithECPrivateKeyFromPEM parses a PEM-encoded ECDSA private key and sets it for signing.
// Suitable for ES256/ES384/ES512.
func WithECPrivateKeyFromPEM(pemBytes []byte) Option {
	return func(o *Options) {
		key, err := jwtV5.ParseECPrivateKeyFromPEM(pemBytes)
		if err != nil {
			return
		}
		o.signingKey = key
	}
}

// WithECPublicKeyFromPEM parses a PEM-encoded ECDSA public key and sets it for verification.
// Suitable for ES256/ES384/ES512.
func WithECPublicKeyFromPEM(pemBytes []byte) Option {
	return func(o *Options) {
		key, err := jwtV5.ParseECPublicKeyFromPEM(pemBytes)
		if err != nil {
			return
		}
		o.keyFunc = func(token *jwtV5.Token) (interface{}, error) {
			return key, nil
		}
	}
}

// WithEd25519PrivateKeyFromPEM parses a PEM-encoded Ed25519 private key and sets it for signing.
// Suitable for EdDSA.
func WithEd25519PrivateKeyFromPEM(pemBytes []byte) Option {
	return func(o *Options) {
		key, err := jwtV5.ParseEdPrivateKeyFromPEM(pemBytes)
		if err != nil {
			return
		}
		o.signingKey = key
	}
}

// WithEd25519PublicKeyFromPEM parses a PEM-encoded Ed25519 public key and sets it for verification.
// Suitable for EdDSA.
func WithEd25519PublicKeyFromPEM(pemBytes []byte) Option {
	return func(o *Options) {
		key, err := jwtV5.ParseEdPublicKeyFromPEM(pemBytes)
		if err != nil {
			return
		}
		o.keyFunc = func(token *jwtV5.Token) (interface{}, error) {
			return key, nil
		}
	}
}
