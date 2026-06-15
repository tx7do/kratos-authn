package hmac

import "time"

// SecretResolver returns the HMAC secret for the given key ID.
// This allows key rotation and per-key secrets.
type SecretResolver func(keyID string) (secret string, ok bool)

// Options holds configuration for the HMAC authenticator.
type Options struct {
	// secrets is a static map of keyID→secret.
	secrets map[string]string

	// resolver is an optional callback for resolving secrets from an
	// external source (database, KMS, etc.).
	resolver SecretResolver

	// maxSkew is the maximum acceptable clock skew for timestamp validation.
	// Defaults to 5 minutes.
	maxSkew time.Duration

	// header names used to extract signature components from metadata.
	keyIDHeader     string
	timestampHeader string
	signatureHeader string
}

type Option func(o *Options)

// WithSecret adds a keyID/secret pair to the static secret map.
func WithSecret(keyID, secret string) Option {
	return func(o *Options) {
		if o.secrets == nil {
			o.secrets = make(map[string]string)
		}
		o.secrets[keyID] = secret
	}
}

// WithSecrets sets the entire static keyID→secret map.
func WithSecrets(secrets map[string]string) Option {
	return func(o *Options) { o.secrets = secrets }
}

// WithSecretResolver sets a callback for resolving secrets from an external source.
func WithSecretResolver(fn SecretResolver) Option {
	return func(o *Options) { o.resolver = fn }
}

// WithMaxSkew sets the maximum acceptable clock skew for timestamp validation.
func WithMaxSkew(d time.Duration) Option {
	return func(o *Options) { o.maxSkew = d }
}

func (o *Options) getSecret(keyID string) (string, bool) {
	if o.resolver != nil {
		return o.resolver(keyID)
	}
	if o.secrets == nil {
		return "", false
	}
	s, ok := o.secrets[keyID]
	return s, ok
}

func (o *Options) getMaxSkew() time.Duration {
	if o.maxSkew > 0 {
		return o.maxSkew
	}
	return 5 * time.Minute
}
