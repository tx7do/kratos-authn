package basicauth

// CredentialValidator is a callback that verifies whether the given
// username/password pair is valid. Returning a non-nil AuthClaims allows
// the caller to populate subject, roles, etc.
type CredentialValidator func(username, password string) (valid bool)

// Options holds configuration for the Basic-Auth authenticator.
type Options struct {
	// users is a static username→password map used when no Validator is set.
	users map[string]string

	// validator is an optional callback for verifying credentials
	// against an external source (database, LDAP, etc.).
	validator CredentialValidator
}

type Option func(o *Options)

// WithUser adds a single username/password entry to the static credential map.
// May be called multiple times.
func WithUser(username, password string) Option {
	return func(o *Options) {
		if o.users == nil {
			o.users = make(map[string]string)
		}
		o.users[username] = password
	}
}

// WithUsers sets the entire static username→password map, replacing any
// previously added entries.
func WithUsers(users map[string]string) Option {
	return func(o *Options) {
		o.users = users
	}
}

// WithValidator sets a callback for verifying credentials against an
// external source. When set, it takes precedence over the static map.
func WithValidator(fn CredentialValidator) Option {
	return func(o *Options) {
		o.validator = fn
	}
}
