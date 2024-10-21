package oidc

import (
	keyfuncV3 "github.com/MicahParks/keyfunc/v3"
)

// Configurator is the interface that wraps the configuration and keyfunc methods.
type Configurator interface {
	// GetConfiguration returns the configuration for the authenticator.
	GetConfiguration() (*ProviderConfig, error)

	// GetKeyfunc returns the keyfunc for the authenticator.
	GetKeyfunc() (keyfuncV3.Keyfunc, error)
}
