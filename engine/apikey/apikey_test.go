package apikey

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	engine "github.com/tx7do/kratos-authn/engine"
)

// ---------------------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------------------

func createAuthCtx(token string) context.Context {
	md := metadata.Pairs(engine.HeaderAuthorize, engine.BearerWord+" "+token)
	return metadata.NewIncomingContext(context.Background(), md)
}

// ---------------------------------------------------------------------------
// NewAuthenticator / Options
// ---------------------------------------------------------------------------

func TestNewAuthenticator_WithKeys(t *testing.T) {
	auth, err := NewAuthenticator(WithKeys([]string{"key-1", "key-2"}))
	require.Nil(t, err)
	require.NotNil(t, auth)
}

func TestNewAuthenticator_WithKeyClaims(t *testing.T) {
	auth, err := NewAuthenticator(
		WithKeys([]string{"key-1"}),
		WithKeyClaims("key-1", map[string]interface{}{
			engine.ClaimFieldSubject: "alice",
		}),
	)
	require.Nil(t, err)
	require.NotNil(t, auth)
}

func TestNewAuthenticator_WithValidator(t *testing.T) {
	auth, err := NewAuthenticator(WithValidator(func(key string) (map[string]interface{}, bool) {
		if key == "valid-key" {
			return map[string]interface{}{engine.ClaimFieldSubject: "bob"}, true
		}
		return nil, false
	}))
	require.Nil(t, err)
	require.NotNil(t, auth)
}

// ---------------------------------------------------------------------------
// AuthenticateToken
// ---------------------------------------------------------------------------

func TestAuthenticateToken_Valid_StaticKeys(t *testing.T) {
	auth, _ := NewAuthenticator(WithKeys([]string{"key-1", "key-2"}))
	claims, err := auth.AuthenticateToken("key-1")
	require.Nil(t, err)
	require.NotNil(t, claims)
}

func TestAuthenticateToken_Valid_WithKeyClaims(t *testing.T) {
	auth, _ := NewAuthenticator(
		WithKeys([]string{"key-1"}),
		WithKeyClaims("key-1", map[string]interface{}{engine.ClaimFieldSubject: "alice"}),
	)
	claims, err := auth.AuthenticateToken("key-1")
	require.Nil(t, err)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "alice", sub)
}

func TestAuthenticateToken_Valid_Validator(t *testing.T) {
	auth, _ := NewAuthenticator(WithValidator(func(key string) (map[string]interface{}, bool) {
		if key == "valid-key" {
			return map[string]interface{}{engine.ClaimFieldSubject: "bob"}, true
		}
		return nil, false
	}))
	claims, err := auth.AuthenticateToken("valid-key")
	require.Nil(t, err)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "bob", sub)
}

func TestAuthenticateToken_InvalidKey_StaticKeys(t *testing.T) {
	auth, _ := NewAuthenticator(WithKeys([]string{"key-1"}))
	_, err := auth.AuthenticateToken("bad-key")
	assert.Equal(t, engine.ErrUnauthenticated, err)
}

func TestAuthenticateToken_InvalidKey_Validator(t *testing.T) {
	auth, _ := NewAuthenticator(WithValidator(func(key string) (map[string]interface{}, bool) {
		return nil, false
	}))
	_, err := auth.AuthenticateToken("bad-key")
	assert.Equal(t, engine.ErrUnauthenticated, err)
}

func TestAuthenticateToken_NoKeysConfigured(t *testing.T) {
	auth, _ := NewAuthenticator()
	_, err := auth.AuthenticateToken("any-key")
	assert.Equal(t, engine.ErrUnauthenticated, err)
}

// ---------------------------------------------------------------------------
// Authenticate (via gRPC context)
// ---------------------------------------------------------------------------

func TestAuthenticate_Success(t *testing.T) {
	auth, _ := NewAuthenticator(WithKeys([]string{"key-1"}))
	ctx := createAuthCtx("key-1")
	claims, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	require.Nil(t, err)
	require.NotNil(t, claims)
}

func TestAuthenticate_MissingToken(t *testing.T) {
	auth, _ := NewAuthenticator(WithKeys([]string{"key-1"}))
	_, err := auth.Authenticate(context.Background(), engine.ContextTypeGrpc)
	assert.Equal(t, engine.ErrMissingBearerToken, err)
}

func TestAuthenticate_InvalidToken(t *testing.T) {
	auth, _ := NewAuthenticator(WithKeys([]string{"key-1"}))
	ctx := createAuthCtx("bad-key")
	_, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	assert.Equal(t, engine.ErrUnauthenticated, err)
}

// ---------------------------------------------------------------------------
// CreateIdentity
// ---------------------------------------------------------------------------

func TestCreateIdentity_Success(t *testing.T) {
	auth, _ := NewAuthenticator(WithKeys([]string{"key-1"}))
	claims := engine.AuthClaims{engine.ClaimFieldSubject: "key-1"}
	token, err := auth.CreateIdentity(claims)
	require.Nil(t, err)
	assert.Equal(t, "key-1", token)
}

func TestCreateIdentityWithContext_Success(t *testing.T) {
	auth, _ := NewAuthenticator(WithKeys([]string{"key-1"}))
	claims := engine.AuthClaims{engine.ClaimFieldSubject: "key-1"}
	ctx, err := auth.CreateIdentityWithContext(context.Background(), engine.ContextTypeGrpc, claims)
	require.Nil(t, err)
	require.NotNil(t, ctx)
}

// ---------------------------------------------------------------------------
// Close / interface compliance
// ---------------------------------------------------------------------------

func TestClose_NoError(t *testing.T) {
	auth, _ := NewAuthenticator(WithKeys([]string{"key-1"}))
	auth.Close()
}

func TestInterfaceCompliance(t *testing.T) {
	var _ engine.Authenticator = (*Authenticator)(nil)
}
