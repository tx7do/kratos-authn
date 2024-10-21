package jwt

import (
	"context"
	"errors"

	jwtV5 "github.com/golang-jwt/jwt/v5"

	"github.com/tx7do/kratos-authn/engine"
	"github.com/tx7do/kratos-authn/engine/utils"
)

var _ engine.Authenticator = (*Authenticator)(nil)

type Authenticator struct {
	options *Options
}

func NewAuthenticator(opts ...Option) (engine.Authenticator, error) {
	auth := &Authenticator{
		options: &Options{},
	}

	for _, o := range opts {
		o(auth.options)
	}

	if auth.options.signingMethod == nil {
		auth.options.signingMethod = jwtV5.SigningMethodHS256
	}

	return auth, nil
}

// Authenticate authenticates the token string and returns the claims.
func (jwt *Authenticator) Authenticate(ctx context.Context, contextType engine.ContextType) (*engine.AuthClaims, error) {
	tokenString, err := utils.AuthFromMD(ctx, utils.BearerWord, contextType)
	if err != nil {
		return nil, engine.ErrMissingBearerToken
	}

	return jwt.AuthenticateToken(tokenString)
}

// AuthenticateToken authenticates the token string and returns the claims.
func (jwt *Authenticator) AuthenticateToken(tokenString string) (*engine.AuthClaims, error) {
	jwtToken, err := jwt.parseToken(tokenString)

	if jwtToken == nil {
		return nil, engine.ErrInvalidToken
	}

	if err != nil {
		switch {
		case errors.Is(err, jwtV5.ErrTokenMalformed):
			return nil, engine.ErrInvalidToken
		case errors.Is(err, jwtV5.ErrTokenSignatureInvalid):
			return nil, engine.ErrSignTokenFailed
		case errors.Is(err, jwtV5.ErrTokenExpired) || errors.Is(err, jwtV5.ErrTokenNotValidYet):
			return nil, engine.ErrTokenExpired
		default:
			return nil, engine.ErrInvalidToken
		}
	}

	if !jwtToken.Valid {
		return nil, engine.ErrInvalidToken
	}
	if jwtToken.Method != jwt.options.signingMethod {
		return nil, engine.ErrUnsupportedSigningMethod
	}
	if jwtToken.Claims == nil {
		return nil, engine.ErrInvalidClaims
	}

	claims, ok := jwtToken.Claims.(jwtV5.MapClaims)
	if !ok {
		return nil, engine.ErrInvalidClaims
	}

	authClaims, err := utils.MapClaimsToAuthClaims(claims)
	if err != nil {
		return nil, err
	}

	return authClaims, nil
}

// CreateIdentityWithContext creates a signed token string from the claims and sets it to the context.
func (jwt *Authenticator) CreateIdentityWithContext(ctx context.Context, contextType engine.ContextType, claims engine.AuthClaims) (context.Context, error) {
	strToken, err := jwt.CreateIdentity(claims)
	if err != nil {
		return ctx, err
	}

	ctx = utils.MDWithAuth(ctx, utils.BearerWord, strToken, contextType)

	return ctx, nil
}

// CreateIdentity creates a signed token string from the claims.
func (jwt *Authenticator) CreateIdentity(claims engine.AuthClaims) (string, error) {
	jwtToken := jwtV5.NewWithClaims(jwt.options.signingMethod, utils.AuthClaimsToJwtClaims(claims))

	strToken, err := jwt.generateToken(jwtToken)
	if err != nil {
		return "", err
	}

	return strToken, nil
}

func (jwt *Authenticator) Close() {}

// parseToken parses the token string and returns the token.
func (jwt *Authenticator) parseToken(token string) (*jwtV5.Token, error) {
	if jwt.options.keyFunc == nil {
		return nil, engine.ErrMissingKeyFunc
	}

	return jwtV5.Parse(token, jwt.options.keyFunc)
}

// generateToken generates a signed token string from the token.
func (jwt *Authenticator) generateToken(jwtToken *jwtV5.Token) (string, error) {
	if jwt.options.keyFunc == nil {
		return "", engine.ErrMissingKeyFunc
	}

	key, err := jwt.options.keyFunc(jwtToken)
	if err != nil {
		return "", engine.ErrGetKeyFailed
	}

	strToken, err := jwtToken.SignedString(key)
	if err != nil {
		return "", engine.ErrSignTokenFailed
	}

	return strToken, nil
}
