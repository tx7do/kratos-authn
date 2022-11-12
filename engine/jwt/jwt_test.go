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

func TestAuthenticator(t *testing.T) {
	ctx := context.Background()

	ctx = transport.NewServerContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})
	ctx = transport.NewClientContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})

	auth, err := NewAuthenticator("test", "HS256")
	assert.Nil(t, err)

	principal := engine.AuthClaims{
		Subject: "user_name",
		Scopes:  make(engine.ScopeSet),
	}
	principal.Scopes["local:admin:user_name"] = true
	principal.Scopes["tenant:admin:user_name"] = true

	outToken, err := auth.CreateIdentity(ctx, principal)
	assert.Nil(t, err)
	assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6ImxvY2FsOmFkbWluOnVzZXJfbmFtZSB0ZW5hbnQ6YWRtaW46dXNlcl9uYW1lIiwic3ViIjoidXNlcl9uYW1lIn0.ln7zjnOKrhZCsAaQQf6vodIz5urxkVphOo7EpI7tv7Y", outToken)

	var token string
	if header, ok := transport.FromClientContext(ctx); ok {
		str := header.RequestHeader().Get("Authorization")
		splits := strings.SplitN(str, " ", 2)
		assert.Equal(t, 2, len(splits))
		assert.Equal(t, utils.BearerWord, splits[0])
		token = str
		//fmt.Println(token)
	}

	if header, ok := transport.FromServerContext(ctx); ok {
		header.RequestHeader().Set("Authorization", token)
	}

	authToken, err := auth.Authenticate(ctx)
	assert.Nil(t, err)
	assert.Equal(t, "user_name", authToken.Subject)
	assert.True(t, authToken.Scopes["local:admin:user_name"])
	assert.True(t, authToken.Scopes["tenant:admin:user_name"])
	fmt.Println(authToken)
}
