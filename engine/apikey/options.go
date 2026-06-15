package apikey

// KeyValidator is a callback that validates an API key and returns the
// claims associated with it (e.g. subject, scopes).
// Return false to reject the key.
type KeyValidator func(apiKey string) (claims map[string]interface{}, valid bool)

// Options holds configuration for the API-Key authenticator.
type Options struct {
	// keys is a static set of valid API keys.
	keys map[string]bool

	// claims is an optional map of key→claims for populating AuthClaims
	// when using the static key set.
	claims map[string]map[string]interface{}

	// validator is an optional callback for validating keys against an
	// external source (database, cache, etc.).
	validator KeyValidator
}

type Option func(o *Options)

// WithKeys sets the static set of valid API keys.
func WithKeys(keys []string) Option {
	return func(o *Options) {
		o.keys = make(map[string]bool)
		for _, k := range keys {
			o.keys[k] = true
		}
	}
}

// WithKeyClaims associates a specific API key with a set of claims.
// When the key is validated, the associated claims will be returned.
func WithKeyClaims(apiKey string, claims map[string]interface{}) Option {
	return func(o *Options) {
		if o.claims == nil {
			o.claims = make(map[string]map[string]interface{})
		}
		o.claims[apiKey] = claims
	}
}

// WithValidator sets a callback for validating API keys and returning
// associated claims from an external source.
func WithValidator(fn KeyValidator) Option {
	return func(o *Options) {
		o.validator = fn
	}
}
