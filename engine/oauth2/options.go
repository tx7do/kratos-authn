package oauth2

import (
	"net/http"
	"time"
)

// Options holds configuration for the OAuth2 token-introspection authenticator.
type Options struct {
	// introspectURL is the RFC 7662 token introspection endpoint.
	introspectURL string

	// clientID and clientSecret are used for authenticating the
	// introspection request (HTTP Basic auth).
	clientID     string
	clientSecret string

	// httpClient allows the caller to inject a custom HTTP client
	// (timeouts, TLS, etc.). Defaults to a standard client with a 10s timeout.
	httpClient *http.Client

	// extraClaimsKeys specifies additional claim keys to copy from the
	// introspection response into AuthClaims (beyond the standard ones).
	extraClaimsKeys []string
}

type Option func(o *Options)

// WithIntrospectURL sets the RFC 7662 token introspection endpoint.
func WithIntrospectURL(url string) Option {
	return func(o *Options) { o.introspectURL = url }
}

// WithClientCredentials sets the client credentials used for
// authenticating the introspection request.
func WithClientCredentials(clientID, clientSecret string) Option {
	return func(o *Options) {
		o.clientID = clientID
		o.clientSecret = clientSecret
	}
}

// WithHTTPClient sets a custom HTTP client for the introspection request.
func WithHTTPClient(c *http.Client) Option {
	return func(o *Options) { o.httpClient = c }
}

// WithExtraClaimsKeys specifies additional keys to copy from the
// introspection response into AuthClaims.
func WithExtraClaimsKeys(keys ...string) Option {
	return func(o *Options) { o.extraClaimsKeys = append(o.extraClaimsKeys, keys...) }
}

func (o *Options) getHTTPClient() *http.Client {
	if o.httpClient != nil {
		return o.httpClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}
