// Package basicauth implements an [engine.Authenticator] that validates
// HTTP Basic credentials (RFC 7617).
//
// The token passed via the "Authorization" header uses the "Basic" scheme:
//
//	Authorization: Basic base64(username:password)
//
// Authentication can use a static user/password map (WithUser / WithUsers)
// or a custom callback (WithValidator) for verifying against an external
// source such as a database or LDAP.
package basicauth

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/tx7do/kratos-authn/engine"
)

// Authenticator validates Basic-Auth credentials.
type Authenticator struct {
	options *Options
}

var _ engine.Authenticator = (*Authenticator)(nil)

// NewAuthenticator creates a Basic-Auth authenticator from the given options.
func NewAuthenticator(opts ...Option) (engine.Authenticator, error) {
	auth := &Authenticator{options: &Options{}}
	for _, o := range opts {
		o(auth.options)
	}
	return auth, nil
}

// Authenticate extracts the Basic-Auth token from the incoming metadata and
// validates the credentials.
func (a *Authenticator) Authenticate(ctx context.Context, contextType engine.ContextType) (*engine.AuthClaims, error) {
	tokenString, err := engine.AuthFromMD(ctx, engine.BasicWord, contextType)
	if err != nil {
		return nil, engine.ErrMissingBearerToken
	}
	return a.AuthenticateToken(tokenString)
}

// AuthenticateToken decodes the base64 credential string and validates
// the username/password pair.
func (a *Authenticator) AuthenticateToken(token string) (*engine.AuthClaims, error) {
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, engine.ErrInvalidToken
	}

	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return nil, engine.ErrInvalidToken
	}

	if !a.validate(username, password) {
		return nil, engine.ErrUnauthenticated
	}

	return &engine.AuthClaims{
		engine.ClaimFieldSubject: username,
	}, nil
}

// CreateIdentityWithContext injects Basic-Auth credentials into the outgoing
// metadata.
func (a *Authenticator) CreateIdentityWithContext(ctx context.Context, contextType engine.ContextType, claims engine.AuthClaims) (context.Context, error) {
	token, err := a.CreateIdentity(claims)
	if err != nil {
		return ctx, err
	}
	ctx = engine.MDWithAuth(ctx, engine.BasicWord, token, contextType)
	return ctx, nil
}

// CreateIdentity encodes the subject (username) and its password from the
// static map into a base64 credential string. Returns an error when no
// static credentials are configured.
func (a *Authenticator) CreateIdentity(claims engine.AuthClaims) (string, error) {
	username, _ := claims.GetSubject()
	if username == "" {
		return "", errors.New("subject is required in claims")
	}

	password, ok := a.options.users[username]
	if !ok {
		return "", errors.New("no password configured for user")
	}

	cred := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(cred)), nil
}

func (a *Authenticator) Close() {}

// validate checks the username/password pair against the validator callback
// or the static map.
func (a *Authenticator) validate(username, password string) bool {
	if a.options.validator != nil {
		return a.options.validator(username, password)
	}
	if a.options.users == nil {
		return false
	}
	expected, ok := a.options.users[username]
	return ok && expected == password
}
