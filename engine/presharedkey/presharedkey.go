package presharedkey

import (
	"context"
	"errors"
	"math/rand"

	"github.com/tx7do/kratos-authn/engine"
	"github.com/tx7do/kratos-authn/engine/utils"
)

type KeySet map[string]bool

type Authenticator struct {
	ValidKeys KeySet
}

var _ engine.Authenticator = (*Authenticator)(nil)

func NewAuthenticator(validKeys []string) (engine.Authenticator, error) {
	if len(validKeys) < 1 {
		return nil, errors.New("invalid auth configuration, please specify at least one key")
	}

	vKeys := make(KeySet, 0)
	for _, k := range validKeys {
		vKeys[k] = true
	}

	return &Authenticator{ValidKeys: vKeys}, nil
}

func (pka *Authenticator) Authenticate(ctx context.Context) (*engine.AuthClaims, error) {
	tokenString, err := utils.AuthFromMD(ctx, utils.BearerWord, false)
	if err != nil {
		return nil, engine.ErrMissingBearerToken
	}

	if _, found := pka.ValidKeys[tokenString]; found {
		return &engine.AuthClaims{
			Subject: "",
		}, nil
	}

	return nil, engine.ErrUnauthenticated
}

func (pka *Authenticator) randomGetKey() string {
	count := len(pka.ValidKeys)
	if count == 0 {
		return ""
	}

	idx := rand.Intn(count)
	for k := range pka.ValidKeys {
		if idx == 0 {
			return k
		}
		idx--
	}

	return ""
}

func (pka *Authenticator) CreateIdentity(requestContext context.Context, _ engine.AuthClaims) (string, error) {
	token := pka.randomGetKey()
	utils.MDWithAuth(requestContext, utils.BearerWord, token, false)
	return token, nil
}

func (pka *Authenticator) Close() {}
