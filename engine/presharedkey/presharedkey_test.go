package presharedkey

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/go-kratos/kratos/v2/transport"
	"github.com/stretchr/testify/assert"

	"github.com/tx7do/kratos-authn/engine"
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

	token := "test_token"

	auth, err := NewAuthenticator(
		WithKeys([]string{token}),
	)
	assert.Nil(t, err)
	assert.NotNil(t, auth)

	principal := engine.AuthClaims{
		Subject: "",
		Scopes:  make(engine.ScopeSet),
	}

	outToken, err := auth.CreateIdentity(principal)
	assert.Nil(t, err)
	assert.Equal(t, token, outToken)

	if header, ok := transport.FromClientContext(ctx); ok {
		str := header.RequestHeader().Get("Authorization")
		splits := strings.SplitN(str, " ", 2)
		assert.Equal(t, 2, len(splits))
		assert.Equal(t, utils.BearerWord, splits[0])
		//fmt.Println(token)
	}

	if header, ok := transport.FromServerContext(ctx); ok {
		header.RequestHeader().Set("Authorization", utils.BearerWord+" "+token)
	}

	authToken, err := auth.Authenticate(ctx, engine.ContextTypeKratosMetaData)
	assert.Nil(t, err)
	assert.Equal(t, "", authToken.Subject)
	fmt.Println(authToken)
}
