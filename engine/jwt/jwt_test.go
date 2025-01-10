package jwt

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/go-kratos/kratos/v2/transport"
	"github.com/stretchr/testify/assert"

	"github.com/tx7do/kratos-authn/engine"
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

// Add append value to key-values pair.
func (hc headerCarrier) Add(key string, value string) {
	http.Header(hc).Add(key, value)
}

// Values returns a slice of values associated with the passed key.
func (hc headerCarrier) Values(key string) []string {
	return http.Header(hc).Values(key)
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

func TestAuthenticator(t *testing.T) {
	ctx := context.Background()

	ctx = transport.NewServerContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})
	ctx = transport.NewClientContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})

	auth, err := NewAuthenticator(
		WithKey([]byte("test")),
		WithSigningMethod("HS256"),
	)
	assert.Nil(t, err)

	scopes := []string{"local:admin:user_name", "tenant:admin:user_name"}

	principal := engine.AuthClaims{
		engine.ClaimFieldSubject: "user_name",
		engine.ClaimFieldScope:   scopes,
	}

	outToken, err := auth.CreateIdentity(principal)
	assert.Nil(t, err)
	assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJsb2NhbDphZG1pbjp1c2VyX25hbWUiLCJ0ZW5hbnQ6YWRtaW46dXNlcl9uYW1lIl0sInN1YiI6InVzZXJfbmFtZSJ9.xIzbQbQSlzdms5ZVaHrg6pZohDlt0DTYopobUo2qqQw", outToken)

	ctx, err = auth.CreateIdentityWithContext(ctx, engine.ContextTypeKratosMetaData, principal)
	assert.Nil(t, err)

	var token string
	if header, ok := transport.FromClientContext(ctx); ok {
		str := header.RequestHeader().Get("Authorization")
		splits := strings.SplitN(str, " ", 2)
		assert.Equal(t, 2, len(splits))
		assert.Equal(t, engine.BearerWord, splits[0])
		token = str
		//fmt.Println(token)
	}

	if header, ok := transport.FromServerContext(ctx); ok {
		header.RequestHeader().Set("Authorization", token)
	}

	authToken, err := auth.Authenticate(ctx, engine.ContextTypeKratosMetaData)
	assert.Nil(t, err)

	sub, _ := authToken.GetSubject()
	assert.Equal(t, "user_name", sub)

	scopesOut, _ := authToken.GetScopes()
	assert.Equal(t, 2, len(scopesOut))
	assert.Equal(t, "local:admin:user_name", scopesOut[0])
	assert.Equal(t, "tenant:admin:user_name", scopesOut[1])
	fmt.Println(authToken)
}
