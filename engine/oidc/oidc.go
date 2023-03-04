package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/hashicorp/go-retryablehttp"

	"github.com/tx7do/kratos-authn/engine"
	"github.com/tx7do/kratos-authn/engine/utils"
)

var (
	jwkRefreshInterval, _ = time.ParseDuration("48h")
)

var _ engine.Authenticator = (*Authenticator)(nil)
var _ Configurator = (*Authenticator)(nil)

type Authenticator struct {
	options *Options

	JwksURI string
	JWKs    *keyfunc.JWKS

	signingMethod jwt.SigningMethod

	httpClient *http.Client
}

func NewAuthenticator(opts ...Option) (engine.Authenticator, error) {
	oidc := &Authenticator{
		options: &Options{},

		httpClient: retryablehttp.NewClient().StandardClient(),
	}

	for _, o := range opts {
		o(oidc.options)
	}

	if oidc.options.signingMethod == nil {
		oidc.options.signingMethod = jwt.SigningMethodRS256
	}

	if err := oidc.fetchKeys(); err != nil {
		return nil, err
	}

	//fmt.Println(oidc.JWKs.KIDs())

	return oidc, nil
}

func (oidc *Authenticator) parseToken(token string) (*jwt.Token, error) {
	return jwt.Parse(token, oidc.JWKs.Keyfunc)
}

func (oidc *Authenticator) Authenticate(requestContext context.Context, contextType engine.ContextType) (*engine.AuthClaims, error) {
	tokenString, err := utils.AuthFromMD(requestContext, utils.BearerWord, contextType)
	if err != nil {
		return nil, engine.ErrMissingBearerToken
	}

	//jwtParser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	//
	//token, err := jwtParser.Parse(tokenString, func(token *jwt.Token) (any, error) {
	//	return oidc.JWKs.Keyfunc(token)
	//})
	//if err != nil {
	//	return nil, engine.ErrInvalidToken
	//}

	return oidc.AuthenticateToken(tokenString)
}

func (oidc *Authenticator) AuthenticateToken(token string) (*engine.AuthClaims, error) {
	jwtToken, err := oidc.parseToken(token)
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

	if !jwtToken.Valid {
		return nil, engine.ErrInvalidToken
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, engine.ErrInvalidClaims
	}

	if ok := claims.VerifyIssuer(oidc.options.IssuerURL, true); !ok {
		return nil, engine.ErrInvalidIssuer
	}

	if ok := claims.VerifyAudience(oidc.options.Audience, true); !ok {
		return nil, engine.ErrInvalidAudience
	}

	principal, err := utils.MapClaimsToAuthClaims(claims)
	if err != nil {
		return nil, err
	}

	return principal, nil
}

func (oidc *Authenticator) CreateIdentityWithContext(ctx context.Context, _ engine.ContextType, _ engine.AuthClaims) (context.Context, error) {
	return ctx, nil
}

func (oidc *Authenticator) CreateIdentity(_ engine.AuthClaims) (string, error) {
	return "", nil
}

func (oidc *Authenticator) Close() {
	oidc.JWKs.EndBackground()
}

func (oidc *Authenticator) fetchKeys() error {
	oidcConfig, err := oidc.GetConfiguration()
	if err != nil {
		return fmt.Errorf("error fetching OIDC configuration: %w", err)
	}

	oidc.JwksURI = oidcConfig.JWKSURL

	jwks, err := oidc.GetKeys()
	if err != nil {
		return fmt.Errorf("error fetching OIDC keys: %w", err)
	}

	oidc.JWKs = jwks

	return nil
}

func (oidc *Authenticator) GetKeys() (*keyfunc.JWKS, error) {
	jwks, err := keyfunc.Get(oidc.JwksURI, keyfunc.Options{
		Client:          oidc.httpClient,
		RefreshInterval: jwkRefreshInterval,
	})
	if err != nil {
		return nil, fmt.Errorf("error fetching keys from %v: %w", oidc.JwksURI, err)
	}
	return jwks, nil
}

func (oidc *Authenticator) getDiscoveryUri() string {
	return strings.TrimSuffix(oidc.options.IssuerURL, "/") + "/.well-known/openid-configuration"
}

func (oidc *Authenticator) GetConfiguration() (*ProviderConfig, error) {
	wellKnown := oidc.getDiscoveryUri()
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("error forming request to get OIDC: %w", err)
	}

	res, err := oidc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error getting OIDC: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(res.Body)

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code getting OIDC: %v", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	oidcConfig := &ProviderConfig{}
	if err := json.Unmarshal(body, oidcConfig); err != nil {
		return nil, fmt.Errorf("failed parsing document: %w", err)
	}

	if oidcConfig.Issuer == "" {
		return nil, errors.New("missing issuer value")
	}

	if oidcConfig.JWKSURL == "" {
		return nil, errors.New("missing jwks_uri value")
	}

	return oidcConfig, nil
}
