package oidc

import (
	"context"
	"fmt"
	"github.com/tx7do/kratos-authn/engine"
	"net/http"
	"testing"

	"github.com/go-kratos/kratos/v2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tx7do/kratos-authn/engine/mocks"
	"github.com/tx7do/kratos-authn/engine/utils"
)

type headerCarrier http.Header

func (hc headerCarrier) Get(key string) string {
	return http.Header(hc).Get(key)
}

func (hc headerCarrier) Set(key, value string) {
	http.Header(hc).Set(key, value)
}

func (hc headerCarrier) Keys() []string {
	keys := make([]string, 0, len(hc))
	for k := range http.Header(hc) {
		keys = append(keys, k)
	}
	return keys
}

type myTransporter struct {
	reqHeader   headerCarrier
	replyHeader headerCarrier
}

func (t *myTransporter) Kind() transport.Kind            { return "test" }
func (t *myTransporter) Endpoint() string                { return "" }
func (t *myTransporter) Operation() string               { return "" }
func (t *myTransporter) RequestHeader() transport.Header { return t.reqHeader }
func (t *myTransporter) ReplyHeader() transport.Header   { return t.replyHeader }

func TestAuthenticator_Authenticate(t *testing.T) {
	ctx := context.Background()

	ctx = transport.NewServerContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})
	ctx = transport.NewClientContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})

	const localOIDCServerURL = "http://localhost:8083"
	const audience = "kratos.dev"

	trustedIssuerServer, err := mocks.NewMockOidcServer(localOIDCServerURL)
	require.NoError(t, err)

	auth, err := NewAuthenticator(
		WithIssuerURL(localOIDCServerURL),
		WithAudience(audience),
		WithSigningMethod("RS256"),
	)
	assert.Nil(t, err)
	assert.NotNil(t, auth)

	trustedToken, err := trustedIssuerServer.GetToken(audience, "user_name")
	require.NoError(t, err)
	fmt.Println(trustedToken)

	if header, ok := transport.FromServerContext(ctx); ok {
		header.RequestHeader().Set("Authorization", utils.BearerWord+" "+trustedToken)
	}

	authToken, err := auth.Authenticate(ctx, engine.ContextTypeKratosMetaData)
	assert.Nil(t, err)
	assert.Equal(t, "user_name", authToken.Subject)
	fmt.Println(authToken)
}

func TestBuildServerWithOIDCAuthentication(t *testing.T) {
	ctx := context.Background()

	ctx = transport.NewServerContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})
	ctx = transport.NewClientContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})

	const localOIDCServerURL = "http://localhost:8083"
	const audience = "kratos.dev"

	trustedIssuerServer, err := mocks.NewMockOidcServer(localOIDCServerURL)
	require.NoError(t, err)

	trustedToken, err := trustedIssuerServer.GetToken(audience, "user_name")
	require.NoError(t, err)
	fmt.Println(trustedToken)

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	if header, ok := transport.FromServerContext(ctx); ok {
		header.RequestHeader().Set("Authorization", utils.BearerWord+" "+trustedToken)
	}

	auth, err := NewAuthenticator(
		WithIssuerURL(localOIDCServerURL),
		WithAudience(audience),
		WithSigningMethod("RS256"),
	)
	assert.Nil(t, err)
	assert.NotNil(t, auth)
	fmt.Printf("%T", auth)

	oidcAuth, _ := auth.(OIDCAuthenticator)
	keys, err := oidcAuth.GetKeys()
	assert.Nil(t, err)
	assert.NotNil(t, keys)

	cfg, err := oidcAuth.GetConfiguration()
	assert.Nil(t, err)
	assert.NotNil(t, cfg)
	fmt.Printf("%v\n", cfg)
}
