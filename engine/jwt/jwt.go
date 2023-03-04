package jwt

import (
	"context"

	"github.com/golang-jwt/jwt/v4"

	"github.com/tx7do/kratos-authn/engine"
	"github.com/tx7do/kratos-authn/engine/utils"
)

type Authenticator struct {
	options *Options
}

var _ engine.Authenticator = (*Authenticator)(nil)

func NewAuthenticator(opts ...Option) (engine.Authenticator, error) {
	auth := &Authenticator{
		options: &Options{},
	}

	for _, o := range opts {
		o(auth.options)
	}

	if auth.options.signingMethod == nil {
		auth.options.signingMethod = jwt.SigningMethodHS256
	}

	return auth, nil
}

func (a *Authenticator) Authenticate(ctx context.Context, contextType engine.ContextType) (*engine.AuthClaims, error) {
	tokenString, err := utils.AuthFromMD(ctx, utils.BearerWord, contextType)
	if err != nil {
		return nil, engine.ErrMissingBearerToken
	}

	token, err := a.parseToken(tokenString)
	if err != nil {
		ve, ok := err.(*jwt.ValidationError)
		if !ok {
			return nil, engine.ErrUnauthenticated
		}
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return nil, engine.ErrInvalidToken
		}
		if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			return nil, engine.ErrTokenExpired
		}
		return nil, engine.ErrInvalidToken
	}

	if !token.Valid {
		return nil, engine.ErrInvalidToken
	}
	if token.Method != a.options.signingMethod {
		return nil, engine.ErrUnsupportedSigningMethod
	}
	if token.Claims == nil {
		return nil, engine.ErrInvalidClaims
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, engine.ErrInvalidClaims
	}

	authClaims, err := utils.MapClaimsToAuthClaims(claims)
	if err != nil {
		return nil, err
	}

	return authClaims, nil
}

func (a *Authenticator) CreateIdentity(ctx context.Context, contextType engine.ContextType, claims engine.AuthClaims) (string, error) {
	token := jwt.NewWithClaims(a.options.signingMethod, utils.AuthClaimsToJwtClaims(claims))

	tokenStr, err := a.generateToken(token)
	if err != nil {
		return "", err
	}

	utils.MDWithAuth(ctx, utils.BearerWord, tokenStr, contextType)

	return tokenStr, nil
}

func (a *Authenticator) Close() {}

func (a *Authenticator) parseToken(token string) (*jwt.Token, error) {
	if a.options.keyFunc == nil {
		return nil, engine.ErrMissingKeyFunc
	}

	return jwt.Parse(token, a.options.keyFunc)
}

func (a *Authenticator) generateToken(token *jwt.Token) (string, error) {
	if a.options.keyFunc == nil {
		return "", engine.ErrMissingKeyFunc
	}

	key, err := a.options.keyFunc(token)
	if err != nil {
		return "", engine.ErrGetKeyFailed
	}

	tokenStr, err := token.SignedString(key)
	if err != nil {
		return "", engine.ErrSignTokenFailed
	}

	return tokenStr, nil
}
