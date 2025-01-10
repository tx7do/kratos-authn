package jwt

import (
	"context"
	"errors"

	jwtV5 "github.com/golang-jwt/jwt/v5"

	"github.com/tx7do/kratos-authn/engine"
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
func (a *Authenticator) Authenticate(ctx context.Context, contextType engine.ContextType) (*engine.AuthClaims, error) {
	tokenString, err := engine.AuthFromMD(ctx, engine.BearerWord, contextType)
	if err != nil {
		return nil, engine.ErrMissingBearerToken
	}

	return a.AuthenticateToken(tokenString)
}

// AuthenticateToken authenticates the token string and returns the claims.
func (a *Authenticator) AuthenticateToken(tokenString string) (*engine.AuthClaims, error) {
	jwtToken, err := a.parseToken(tokenString)

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
	if jwtToken.Method != a.options.signingMethod {
		return nil, engine.ErrUnsupportedSigningMethod
	}
	if jwtToken.Claims == nil {
		return nil, engine.ErrInvalidClaims
	}

	claims, ok := jwtToken.Claims.(jwtV5.MapClaims)
	if !ok {
		return nil, engine.ErrInvalidClaims
	}

	authClaim := engine.AuthClaims(claims)

	return &authClaim, nil
}

// CreateIdentityWithContext creates a signed token string from the claims and sets it to the context.
func (a *Authenticator) CreateIdentityWithContext(ctx context.Context, contextType engine.ContextType, claims engine.AuthClaims) (context.Context, error) {
	strToken, err := a.CreateIdentity(claims)
	if err != nil {
		return ctx, err
	}

	ctx = engine.MDWithAuth(ctx, engine.BearerWord, strToken, contextType)

	return ctx, nil
}

// CreateIdentity creates a signed token string from the claims.
func (a *Authenticator) CreateIdentity(claims engine.AuthClaims) (string, error) {
	jwtToken := jwtV5.NewWithClaims(
		a.options.signingMethod,
		&claims,
	)

	strToken, err := a.generateToken(jwtToken)
	if err != nil {
		return "", err
	}

	return strToken, nil
}

func (a *Authenticator) Close() {}

// parseToken parses the token string and returns the token.
func (a *Authenticator) parseToken(token string) (*jwtV5.Token, error) {
	if a.options.keyFunc == nil {
		return nil, engine.ErrMissingKeyFunc
	}

	return jwtV5.Parse(token, a.options.keyFunc)
}

// generateToken generates a signed token string from the token.
func (a *Authenticator) generateToken(jwtToken *jwtV5.Token) (string, error) {
	if a.options.keyFunc == nil {
		return "", engine.ErrMissingKeyFunc
	}

	key, err := a.options.keyFunc(jwtToken)
	if err != nil {
		return "", engine.ErrGetKeyFailed
	}

	strToken, err := jwtToken.SignedString(key)
	if err != nil {
		return "", engine.ErrSignTokenFailed
	}

	return strToken, nil
}
