package presharedkey

type KeySet map[string]bool

type Options struct {
	ValidKeys KeySet
}

type Option func(d *Options)

// WithKeys set key set
func WithKeys(validKeys []string) Option {
	return func(o *Options) {
		vKeys := make(KeySet, 0)
		for _, k := range validKeys {
			vKeys[k] = true
		}

		o.ValidKeys = vKeys
	}
}
