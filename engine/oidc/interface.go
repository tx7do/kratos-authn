package oidc

import "github.com/MicahParks/keyfunc"

type Configurator interface {
	GetConfiguration() (*ProviderConfig, error)
	GetKeys() (*keyfunc.JWKS, error)
}
