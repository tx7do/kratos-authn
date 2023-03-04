package oidc

// ProviderConfig allows creating providers when discovery isn't supported. It's
// generally easier to use NewProvider directly.
// See https://datatracker.ietf.org/doc/html/rfc8414#section-2
type ProviderConfig struct {
	// IssuerURL is the identity of the provider, and the string it uses to sign
	// ID tokens with. For example "https://accounts.google.com". This value MUST
	// match ID tokens exactly.
	Issuer string `json:"issuer"`

	// AuthURL is the endpoint used by the provider to support the OAuth 2.0
	// authorization endpoint.
	AuthURL string `json:"authorization_endpoint"`

	// TokenURL is the endpoint used by the provider to support the OAuth 2.0
	// token endpoint.
	TokenURL string `json:"token_endpoint"`

	// UserInfoURL is the endpoint used by the provider to support the OpenID
	// Connect UserInfo flow.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	UserInfoURL string `json:"userinfo_endpoint"`

	// JWKSURL is the endpoint used by the provider to advertise public keys to
	// verify issued ID tokens. This endpoint is polled as new keys are made
	// available.
	JWKSURL string `json:"jwks_uri"`

	RevocationURL string `json:"revocation_endpoint"`

	// Algorithms, if provided, indicate a list of JWT algorithms allowed to sign
	// ID tokens. If not provided, this defaults to the algorithms advertised by
	// the JWK endpoint, then the set of algorithms supported by this package.
	Algorithms []string `json:"id_token_signing_alg_values_supported"`
}

// SupportedAlgorithms is a list of algorithms explicitly supported by this
// package. If a provider supports other algorithms, such as HS256 or none,
// those values won't be passed to the IDTokenVerifier.
var SupportedAlgorithms = map[string]bool{
	RS256: true,
	RS384: true,
	RS512: true,
	ES256: true,
	ES384: true,
	ES512: true,
	PS256: true,
	PS384: true,
	PS512: true,
}

type claimSource struct {
	Endpoint    string `json:"endpoint"`
	AccessToken string `json:"access_token"`
}
