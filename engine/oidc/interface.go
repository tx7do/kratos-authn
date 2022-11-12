package oidc

import "github.com/MicahParks/keyfunc"

type OIDCAuthenticator interface {
	GetConfiguration() (*ProviderConfig, error)
	GetKeys() (*keyfunc.JWKS, error)
}
