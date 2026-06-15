package basicauth

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	engine "github.com/tx7do/kratos-authn/engine"
)

// ---------------------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------------------

func createAuthCtx(scheme, token string) context.Context {
	md := metadata.Pairs(engine.HeaderAuthorize, scheme+" "+token)
	return metadata.NewIncomingContext(context.Background(), md)
}

func encodeCred(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

// ---------------------------------------------------------------------------
// NewAuthenticator / Options
// ---------------------------------------------------------------------------

func TestNewAuthenticator_WithUsers(t *testing.T) {
	auth, err := NewAuthenticator(WithUsers(map[string]string{"alice": "wonderland"}))
	require.Nil(t, err)
	require.NotNil(t, auth)
}

func TestNewAuthenticator_WithMultipleUsers(t *testing.T) {
	auth, err := NewAuthenticator(
		WithUser("alice", "wonderland"),
		WithUser("bob", "builder"),
	)
	require.Nil(t, err)
	require.NotNil(t, auth)
}

func TestNewAuthenticator_WithValidator(t *testing.T) {
	auth, err := NewAuthenticator(WithValidator(func(u, p string) bool {
		return u == "admin" && p == "secret"
	}))
	require.Nil(t, err)
	require.NotNil(t, auth)
}

// ---------------------------------------------------------------------------
// AuthenticateToken
// ---------------------------------------------------------------------------

func TestAuthenticateToken_Valid_StaticMap(t *testing.T) {
	auth, _ := NewAuthenticator(WithUser("alice", "wonderland"))
	claims, err := auth.AuthenticateToken(encodeCred("alice", "wonderland"))
	require.Nil(t, err)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "alice", sub)
}

func TestAuthenticateToken_Valid_Validator(t *testing.T) {
	auth, _ := NewAuthenticator(WithValidator(func(u, p string) bool {
		return u == "admin" && p == "secret"
	}))
	claims, err := auth.AuthenticateToken(encodeCred("admin", "secret"))
	require.Nil(t, err)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "admin", sub)
}

func TestAuthenticateToken_WrongPassword(t *testing.T) {
	auth, _ := NewAuthenticator(WithUser("alice", "wonderland"))
	_, err := auth.AuthenticateToken(encodeCred("alice", "wrong"))
	assert.Equal(t, engine.ErrUnauthenticated, err)
}

func TestAuthenticateToken_UnknownUser(t *testing.T) {
	auth, _ := NewAuthenticator(WithUser("alice", "wonderland"))
	_, err := auth.AuthenticateToken(encodeCred("bob", "whatever"))
	assert.Equal(t, engine.ErrUnauthenticated, err)
}

func TestAuthenticateToken_InvalidBase64(t *testing.T) {
	auth, _ := NewAuthenticator(WithUser("alice", "wonderland"))
	_, err := auth.AuthenticateToken("!!!not-base64!!!")
	assert.Equal(t, engine.ErrInvalidToken, err)
}

func TestAuthenticateToken_NoColon(t *testing.T) {
	auth, _ := NewAuthenticator(WithUser("alice", "wonderland"))
	_, err := auth.AuthenticateToken(base64.StdEncoding.EncodeToString([]byte("nopassword")))
	assert.Equal(t, engine.ErrInvalidToken, err)
}

// ---------------------------------------------------------------------------
// Authenticate (via gRPC context)
// ---------------------------------------------------------------------------

func TestAuthenticate_Success(t *testing.T) {
	auth, _ := NewAuthenticator(WithUser("alice", "wonderland"))
	ctx := createAuthCtx(engine.BasicWord, encodeCred("alice", "wonderland"))
	claims, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	require.Nil(t, err)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "alice", sub)
}

func TestAuthenticate_MissingToken(t *testing.T) {
	auth, _ := NewAuthenticator(WithUser("alice", "wonderland"))
	_, err := auth.Authenticate(context.Background(), engine.ContextTypeGrpc)
	assert.Equal(t, engine.ErrMissingBearerToken, err)
}

func TestAuthenticate_WrongScheme(t *testing.T) {
	auth, _ := NewAuthenticator(WithUser("alice", "wonderland"))
	ctx := createAuthCtx(engine.BearerWord, encodeCred("alice", "wonderland"))
	_, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	assert.Equal(t, engine.ErrMissingBearerToken, err)
}

// ---------------------------------------------------------------------------
// CreateIdentity
// ---------------------------------------------------------------------------

func TestCreateIdentity_Success(t *testing.T) {
	auth, _ := NewAuthenticator(WithUser("alice", "wonderland"))
	claims := engine.AuthClaims{engine.ClaimFieldSubject: "alice"}
	token, err := auth.CreateIdentity(claims)
	require.Nil(t, err)

	// round-trip
	decoded, err := auth.AuthenticateToken(token)
	require.Nil(t, err)
	sub, _ := decoded.GetSubject()
	assert.Equal(t, "alice", sub)
}

func TestCreateIdentity_NoSubject(t *testing.T) {
	auth, _ := NewAuthenticator(WithUser("alice", "wonderland"))
	_, err := auth.CreateIdentity(engine.AuthClaims{})
	assert.NotNil(t, err)
}

func TestCreateIdentityWithContext_Success(t *testing.T) {
	auth, _ := NewAuthenticator(WithUser("alice", "wonderland"))
	claims := engine.AuthClaims{engine.ClaimFieldSubject: "alice"}
	ctx, err := auth.CreateIdentityWithContext(context.Background(), engine.ContextTypeGrpc, claims)
	require.Nil(t, err)
	require.NotNil(t, ctx)
}

// ---------------------------------------------------------------------------
// Close / interface compliance
// ---------------------------------------------------------------------------

func TestClose_NoError(t *testing.T) {
	auth, _ := NewAuthenticator(WithUser("alice", "wonderland"))
	auth.Close()
}

func TestInterfaceCompliance(t *testing.T) {
	var _ engine.Authenticator = (*Authenticator)(nil)
}
