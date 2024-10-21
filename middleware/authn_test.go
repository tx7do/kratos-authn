package middleware

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	jwtV5 "github.com/golang-jwt/jwt/v5"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/transport"

	"github.com/tx7do/kratos-authn/engine"
	"github.com/tx7do/kratos-authn/engine/jwt"
	"github.com/tx7do/kratos-authn/engine/utils"
)

type headerCarrier http.Header

func (hc headerCarrier) Get(key string) string { return http.Header(hc).Get(key) }

func (hc headerCarrier) Set(key string, value string) { http.Header(hc).Set(key, value) }

// Add append value to key-values pair.
func (hc headerCarrier) Add(key string, value string) {
	http.Header(hc).Add(key, value)
}

// Values returns a slice of values associated with the passed key.
func (hc headerCarrier) Values(key string) []string {
	return http.Header(hc).Values(key)
}

// Keys lists the keys stored in this carrier.
func (hc headerCarrier) Keys() []string {
	keys := make([]string, 0, len(hc))
	for k := range http.Header(hc) {
		keys = append(keys, k)
	}
	return keys
}

func newTokenHeader(headerKey string, token string) *headerCarrier {
	header := &headerCarrier{}
	header.Set(headerKey, fmt.Sprintf("%s %s", utils.BearerWord, token))
	return header
}

type Transport struct {
	kind      transport.Kind
	endpoint  string
	operation string
	reqHeader transport.Header
}

func (tr *Transport) Kind() transport.Kind {
	return tr.kind
}

func (tr *Transport) Endpoint() string {
	return tr.endpoint
}

func (tr *Transport) Operation() string {
	return tr.operation
}

func (tr *Transport) RequestHeader() transport.Header {
	return tr.reqHeader
}

func (tr *Transport) ReplyHeader() transport.Header {
	return nil
}

func generateJwtKey(key, sub string) string {
	mapClaims := jwtV5.MapClaims{}
	mapClaims["sub"] = sub
	claims := jwtV5.NewWithClaims(jwtV5.SigningMethodHS256, mapClaims)
	token, _ := claims.SignedString([]byte(key))
	return token
}

func TestServer(t *testing.T) {
	testKey := "testKey"

	token := generateJwtKey(testKey, "fly")

	tests := []struct {
		name      string
		ctx       context.Context
		alg       string
		exceptErr error
		key       string
	}{
		{
			name:      "normal",
			ctx:       transport.NewServerContext(context.Background(), &Transport{reqHeader: newTokenHeader(utils.HeaderAuthorize, token)}),
			alg:       "HS256",
			exceptErr: nil,
			key:       testKey,
		},
		{
			name:      "miss token",
			ctx:       transport.NewServerContext(context.Background(), &Transport{reqHeader: headerCarrier{}}),
			alg:       "HS256",
			exceptErr: engine.ErrMissingBearerToken,
			key:       testKey,
		},
		{
			name: "token invalid",
			ctx: transport.NewServerContext(context.Background(), &Transport{
				reqHeader: newTokenHeader(utils.HeaderAuthorize, "12313123"),
			}),
			alg:       "HS256",
			exceptErr: engine.ErrInvalidToken,
			key:       testKey,
		},
		{
			name:      "method invalid",
			ctx:       transport.NewServerContext(context.Background(), &Transport{reqHeader: newTokenHeader(utils.HeaderAuthorize, token)}),
			alg:       "ES384",
			exceptErr: engine.ErrUnsupportedSigningMethod,
			key:       testKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testToken *engine.AuthClaims
			next := func(ctx context.Context, req interface{}) (interface{}, error) {
				t.Log(req)
				testToken, _ = FromContext(ctx)
				t.Log(testToken)
				return "reply", nil
			}

			authenticator, err := jwt.NewAuthenticator(
				jwt.WithKey([]byte(testKey)),
				jwt.WithSigningMethod(test.alg),
			)
			assert.Nil(t, err)

			server := Server(authenticator)(next)

			_, err2 := server(test.ctx, test.name)
			if !errors.Is(test.exceptErr, err2) {
				t.Errorf("except error %v, but got %v", test.exceptErr, err2)
			}
			if test.exceptErr == nil {
				if testToken == nil {
					t.Errorf("except testToken not nil, but got nil")
				}
			}
		})
	}

}

func TestClient(t *testing.T) {
	testKey := "testKey"

	tests := []struct {
		name        string
		expectError error
	}{
		{
			name:        "normal",
			expectError: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			next := func(ctx context.Context, req interface{}) (interface{}, error) {
				if header, ok := transport.FromClientContext(ctx); ok {
					t.Log(header.RequestHeader().Get(utils.HeaderAuthorize))
				}
				return "reply", nil
			}

			authenticator, err := jwt.NewAuthenticator(
				jwt.WithKey([]byte(testKey)),
				jwt.WithSigningMethod("HS256"),
			)
			assert.Nil(t, err)

			principal := engine.AuthClaims{
				Subject: "user_name",
				Scopes:  make(engine.ScopeSet),
			}
			principal.Scopes["local:admin:user_name"] = true
			principal.Scopes["tenant:admin:user_name"] = true

			client := Client(authenticator, WithAuthClaims(principal))(next)
			header := &headerCarrier{}
			_, err2 := client(transport.NewClientContext(context.Background(), &Transport{reqHeader: header}), "ok")
			if !errors.Is(test.expectError, err2) {
				t.Errorf("except error %v, but got %v", test.expectError, err2)
			}
		})
	}
}
