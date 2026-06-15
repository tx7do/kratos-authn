package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

func TestAuthenticatorRS256(t *testing.T) {
	// Generate RSA key pair for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)

	ctx := context.Background()

	ctx = transport.NewServerContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})
	ctx = transport.NewClientContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})

	auth, err := NewAuthenticator(
		WithSigningMethod("RS256"),
		WithSigningKey(privateKey),
		WithVerificationKey(&privateKey.PublicKey),
	)
	assert.Nil(t, err)

	scopes := []string{"local:admin:user_name", "tenant:admin:user_name"}

	principal := engine.AuthClaims{
		engine.ClaimFieldSubject: "user_name",
		engine.ClaimFieldScope:   scopes,
	}

	outToken, err := auth.CreateIdentity(principal)
	assert.Nil(t, err)
	assert.NotEmpty(t, outToken)

	ctx, err = auth.CreateIdentityWithContext(ctx, engine.ContextTypeKratosMetaData, principal)
	assert.Nil(t, err)

	var token string
	if header, ok := transport.FromClientContext(ctx); ok {
		str := header.RequestHeader().Get("Authorization")
		splits := strings.SplitN(str, " ", 2)
		assert.Equal(t, 2, len(splits))
		assert.Equal(t, engine.BearerWord, splits[0])
		token = str
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

func TestAuthenticatorRS256WithPEM(t *testing.T) {
	// Generate RSA key pair for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)

	// Marshal keys to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	assert.Nil(t, err)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	ctx := context.Background()

	ctx = transport.NewServerContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})
	ctx = transport.NewClientContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})

	auth, err := NewAuthenticator(
		WithSigningMethod("RS256"),
		WithPrivateKeyFromPEM(privateKeyPEM),
		WithPublicKeyFromPEM(publicKeyPEM),
	)
	assert.Nil(t, err)

	principal := engine.AuthClaims{
		engine.ClaimFieldSubject: "user_name",
	}

	outToken, err := auth.CreateIdentity(principal)
	assert.Nil(t, err)
	assert.NotEmpty(t, outToken)

	ctx, err = auth.CreateIdentityWithContext(ctx, engine.ContextTypeKratosMetaData, principal)
	assert.Nil(t, err)

	var token string
	if header, ok := transport.FromClientContext(ctx); ok {
		str := header.RequestHeader().Get("Authorization")
		splits := strings.SplitN(str, " ", 2)
		assert.Equal(t, 2, len(splits))
		assert.Equal(t, engine.BearerWord, splits[0])
		token = str
	}

	if header, ok := transport.FromServerContext(ctx); ok {
		header.RequestHeader().Set("Authorization", token)
	}

	authToken, err := auth.Authenticate(ctx, engine.ContextTypeKratosMetaData)
	assert.Nil(t, err)

	sub, _ := authToken.GetSubject()
	assert.Equal(t, "user_name", sub)
}

func TestAuthenticatorES256(t *testing.T) {
	// Generate ECDSA key pair for testing (P-256 curve for ES256)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)

	ctx := context.Background()

	ctx = transport.NewServerContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})
	ctx = transport.NewClientContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})

	auth, err := NewAuthenticator(
		WithSigningMethod("ES256"),
		WithSigningKey(privateKey),
		WithVerificationKey(&privateKey.PublicKey),
	)
	assert.Nil(t, err)

	principal := engine.AuthClaims{
		engine.ClaimFieldSubject: "user_name",
	}

	ctx, err = auth.CreateIdentityWithContext(ctx, engine.ContextTypeKratosMetaData, principal)
	assert.Nil(t, err)

	var token string
	if header, ok := transport.FromClientContext(ctx); ok {
		token = header.RequestHeader().Get("Authorization")
	}

	if header, ok := transport.FromServerContext(ctx); ok {
		header.RequestHeader().Set("Authorization", token)
	}

	authToken, err := auth.Authenticate(ctx, engine.ContextTypeKratosMetaData)
	assert.Nil(t, err)

	sub, _ := authToken.GetSubject()
	assert.Equal(t, "user_name", sub)
}

func TestAuthenticatorES256WithPEM(t *testing.T) {
	// Generate ECDSA key pair (P-256 curve for ES256)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)

	// Marshal to PEM
	privKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	assert.Nil(t, err)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	assert.Nil(t, err)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	ctx := context.Background()

	ctx = transport.NewServerContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})
	ctx = transport.NewClientContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})

	auth, err := NewAuthenticator(
		WithSigningMethod("ES256"),
		WithECPrivateKeyFromPEM(privateKeyPEM),
		WithECPublicKeyFromPEM(publicKeyPEM),
	)
	assert.Nil(t, err)

	principal := engine.AuthClaims{
		engine.ClaimFieldSubject: "user_name",
	}

	ctx, err = auth.CreateIdentityWithContext(ctx, engine.ContextTypeKratosMetaData, principal)
	assert.Nil(t, err)

	var token string
	if header, ok := transport.FromClientContext(ctx); ok {
		token = header.RequestHeader().Get("Authorization")
	}

	if header, ok := transport.FromServerContext(ctx); ok {
		header.RequestHeader().Set("Authorization", token)
	}

	authToken, err := auth.Authenticate(ctx, engine.ContextTypeKratosMetaData)
	assert.Nil(t, err)

	sub, _ := authToken.GetSubject()
	assert.Equal(t, "user_name", sub)
}

func TestAuthenticatorPS256(t *testing.T) {
	// RSA-PSS uses the same RSA key pair as RS256
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)

	ctx := context.Background()

	ctx = transport.NewServerContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})
	ctx = transport.NewClientContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})

	auth, err := NewAuthenticator(
		WithSigningMethod("PS256"),
		WithSigningKey(privateKey),
		WithVerificationKey(&privateKey.PublicKey),
	)
	assert.Nil(t, err)

	principal := engine.AuthClaims{
		engine.ClaimFieldSubject: "user_name",
	}

	ctx, err = auth.CreateIdentityWithContext(ctx, engine.ContextTypeKratosMetaData, principal)
	assert.Nil(t, err)

	var token string
	if header, ok := transport.FromClientContext(ctx); ok {
		token = header.RequestHeader().Get("Authorization")
	}

	if header, ok := transport.FromServerContext(ctx); ok {
		header.RequestHeader().Set("Authorization", token)
	}

	authToken, err := auth.Authenticate(ctx, engine.ContextTypeKratosMetaData)
	assert.Nil(t, err)

	sub, _ := authToken.GetSubject()
	assert.Equal(t, "user_name", sub)
}

func TestAuthenticatorEdDSA(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)

	ctx := context.Background()

	ctx = transport.NewServerContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})
	ctx = transport.NewClientContext(ctx, &myTransporter{reqHeader: headerCarrier{}, replyHeader: headerCarrier{}})

	auth, err := NewAuthenticator(
		WithSigningMethod("EdDSA"),
		WithSigningKey(privateKey),
		WithVerificationKey(publicKey),
	)
	assert.Nil(t, err)

	principal := engine.AuthClaims{
		engine.ClaimFieldSubject: "user_name",
	}

	ctx, err = auth.CreateIdentityWithContext(ctx, engine.ContextTypeKratosMetaData, principal)
	assert.Nil(t, err)

	var token string
	if header, ok := transport.FromClientContext(ctx); ok {
		token = header.RequestHeader().Get("Authorization")
	}

	if header, ok := transport.FromServerContext(ctx); ok {
		header.RequestHeader().Set("Authorization", token)
	}

	authToken, err := auth.Authenticate(ctx, engine.ContextTypeKratosMetaData)
	assert.Nil(t, err)

	sub, _ := authToken.GetSubject()
	assert.Equal(t, "user_name", sub)
}
