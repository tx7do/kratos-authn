package mtls

// CertValidator is a callback that inspects a client certificate's
// subject (CN or SAN) and decides whether it should be accepted.
// Returning true allows the certificate; false rejects it.
type CertValidator func(subject string) (claims map[string]interface{}, valid bool)

// Options holds configuration for the mTLS authenticator.
type Options struct {
	// trustedCNs is a static set of trusted certificate Common Names
	// (or SANs). If non-empty, only certs whose subject matches will
	// be accepted.
	trustedCNs map[string]bool

	// validator is an optional callback for validating certificates
	// against an external source and returning associated claims.
	validator CertValidator
}

type Option func(o *Options)

// WithTrustedCN adds a trusted Common Name / SAN to the static set.
func WithTrustedCN(cn string) Option {
	return func(o *Options) {
		if o.trustedCNs == nil {
			o.trustedCNs = make(map[string]bool)
		}
		o.trustedCNs[cn] = true
	}
}

// WithTrustedCNs sets the entire static set of trusted Common Names / SANs.
func WithTrustedCNs(cns []string) Option {
	return func(o *Options) {
		o.trustedCNs = make(map[string]bool)
		for _, cn := range cns {
			o.trustedCNs[cn] = true
		}
	}
}

// WithValidator sets a callback for validating certificates and returning
// associated claims from an external source.
func WithValidator(fn CertValidator) Option {
	return func(o *Options) { o.validator = fn }
}

func (o *Options) isTrusted(subject string) bool {
	if len(o.trustedCNs) == 0 {
		return true // no restriction → accept all
	}
	return o.trustedCNs[subject]
}
