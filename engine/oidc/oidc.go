package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	keyfuncV3 "github.com/MicahParks/keyfunc/v3"
	jwtV5 "github.com/golang-jwt/jwt/v5"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/tx7do/kratos-authn/engine"
)

//var (
//	jwkRefreshInterval, _ = time.ParseDuration("48h")
//)

var _ engine.Authenticator = (*Authenticator)(nil)
var _ Configurator = (*Authenticator)(nil)

type Authenticator struct {
	options *Options

	JwksURI string
	JWKs    keyfuncV3.Keyfunc

	signingMethod jwtV5.SigningMethod

	httpClient *http.Client
}

func NewAuthenticator(opts ...Option) (engine.Authenticator, error) {
	oidc := &Authenticator{
		options:    &Options{},
		httpClient: retryablehttp.NewClient().StandardClient(),
	}

	for _, o := range opts {
		o(oidc.options)
	}

	if oidc.options.signingMethod == nil {
		oidc.options.signingMethod = jwtV5.SigningMethodRS256
	}

	if err := oidc.fetchKeys(); err != nil {
		return nil, err
	}

	//fmt.Println(oidc.JWKs.KIDs())

	return oidc, nil
}

func (a *Authenticator) parseToken(token string) (*jwtV5.Token, error) {
	return jwtV5.Parse(token, a.JWKs.Keyfunc)
}

func (a *Authenticator) Authenticate(requestContext context.Context, contextType engine.ContextType) (*engine.AuthClaims, error) {
	tokenString, err := engine.AuthFromMD(requestContext, engine.BearerWord, contextType)
	if err != nil {
		return nil, engine.ErrMissingBearerToken
	}

	//jwtParser := jwtV5.NewParser(jwtV5.WithValidMethods([]string{"RS256"}))
	//
	//token, err := jwtParser.Parse(tokenString, func(token *jwtV5.Token) (any, error) {
	//	return a.JWKs.Keyfunc(token)
	//})
	//if err != nil {
	//	return nil, engine.ErrInvalidToken
	//}

	return a.AuthenticateToken(tokenString)
}

func (a *Authenticator) AuthenticateToken(token string) (*engine.AuthClaims, error) {
	jwtToken, err := a.parseToken(token)

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

	claims, ok := jwtToken.Claims.(jwtV5.MapClaims)
	if !ok {
		return nil, engine.ErrInvalidClaims
	}

	var opts []jwtV5.ParserOption
	opts = append(opts, jwtV5.WithIssuer(a.options.IssuerURL))
	opts = append(opts, jwtV5.WithAudience(a.options.Audience))
	validator := jwtV5.NewValidator(opts...)
	err = validator.Validate(claims)
	if err != nil {
		switch {
		case errors.Is(err, jwtV5.ErrTokenInvalidAudience):
			return nil, engine.ErrInvalidAudience
		case errors.Is(err, jwtV5.ErrTokenInvalidIssuer):
			return nil, engine.ErrInvalidIssuer
		default:
			return nil, engine.ErrInvalidToken
		}
	}

	authClaim := engine.AuthClaims(claims)

	return &authClaim, nil
}

func (a *Authenticator) CreateIdentityWithContext(ctx context.Context, _ engine.ContextType, _ engine.AuthClaims) (context.Context, error) {
	return ctx, nil
}

func (a *Authenticator) CreateIdentity(_ engine.AuthClaims) (string, error) {
	return "", nil
}

func (a *Authenticator) Close() {
	//a.JWKs.EndBackground()
}

func (a *Authenticator) fetchKeys() error {
	oidcConfig, err := a.GetConfiguration()
	if err != nil {
		return fmt.Errorf("error fetching OIDC configuration: %w", err)
	}

	a.JwksURI = oidcConfig.JWKSURL

	jwks, err := a.GetKeyfunc()
	if err != nil {
		return fmt.Errorf("error fetching OIDC keys: %w", err)
	}

	a.JWKs = jwks

	return nil
}

func (a *Authenticator) GetKeyfunc() (keyfuncV3.Keyfunc, error) {
	jwks, err := keyfuncV3.NewDefault([]string{a.JwksURI})
	if err != nil {
		return nil, fmt.Errorf("error fetching keys from %v: %w", a.JwksURI, err)
	}
	return jwks, nil
}

func (a *Authenticator) getDiscoveryUri() string {
	return strings.TrimSuffix(a.options.IssuerURL, "/") + "/.well-known/openid-configuration"
}

func (a *Authenticator) GetConfiguration() (*ProviderConfig, error) {
	wellKnown := a.getDiscoveryUri()
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("error forming request to get OIDC: %w", err)
	}

	res, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error getting OIDC: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err = Body.Close()
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
