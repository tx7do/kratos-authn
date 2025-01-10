package presharedkey

import (
	"context"
	"errors"
	"math/rand"

	"github.com/tx7do/kratos-authn/engine"
)

type Authenticator struct {
	options *Options
}

var _ engine.Authenticator = (*Authenticator)(nil)

func NewAuthenticator(opts ...Option) (engine.Authenticator, error) {
	//if len(validKeys) < 1 {
	//	return nil, errors.New("invalid auth configuration, please specify at least one key")
	//}

	auth := &Authenticator{
		options: &Options{},
	}

	for _, o := range opts {
		o(auth.options)
	}

	return auth, nil
}

func (pka *Authenticator) Authenticate(ctx context.Context, contextType engine.ContextType) (*engine.AuthClaims, error) {
	tokenString, err := engine.AuthFromMD(ctx, engine.BearerWord, contextType)
	if err != nil {
		return nil, engine.ErrMissingBearerToken
	}

	return pka.AuthenticateToken(tokenString)
}

func (pka *Authenticator) AuthenticateToken(token string) (*engine.AuthClaims, error) {
	if len(pka.options.ValidKeys) < 1 {
		return nil, errors.New("invalid auth configuration, please specify at least one key")
	}

	if _, found := pka.options.ValidKeys[token]; found {
		return &engine.AuthClaims{}, nil
	}

	return nil, engine.ErrUnauthenticated
}

func (pka *Authenticator) getRandomKey() string {
	count := len(pka.options.ValidKeys)
	if count == 0 {
		return ""
	}

	idx := rand.Intn(count)
	for k := range pka.options.ValidKeys {
		if idx == 0 {
			return k
		}
		idx--
	}

	return ""
}

func (pka *Authenticator) CreateIdentityWithContext(ctx context.Context, contextType engine.ContextType, claims engine.AuthClaims) (context.Context, error) {
	token, err := pka.CreateIdentity(claims)
	if err != nil {
		return ctx, err
	}
	ctx = engine.MDWithAuth(ctx, engine.BearerWord, token, contextType)
	return ctx, nil
}

func (pka *Authenticator) CreateIdentity(_ engine.AuthClaims) (string, error) {
	token := pka.getRandomKey()
	return token, nil
}

func (pka *Authenticator) Close() {}
