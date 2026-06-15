package session

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	engine "github.com/tx7do/kratos-authn/engine"
)

// ---------------------------------------------------------------------------
// NewAuthenticator / Options
// ---------------------------------------------------------------------------

func TestNewAuthenticator_Default(t *testing.T) {
	auth, err := NewAuthenticator()
	require.Nil(t, err)
	require.NotNil(t, auth)
}

func TestNewAuthenticator_WithStore(t *testing.T) {
	store := NewMemoryStore()
	auth, err := NewAuthenticator(WithStore(store))
	require.Nil(t, err)
	require.NotNil(t, auth)
}

func TestNewAuthenticator_WithSessionIDHeader(t *testing.T) {
	auth, err := NewAuthenticator(WithSessionIDHeader("X-Token"))
	require.Nil(t, err)
	require.NotNil(t, auth)
}

// ---------------------------------------------------------------------------
// MemoryStore
// ---------------------------------------------------------------------------

func TestMemoryStore_SetGet(t *testing.T) {
	store := NewMemoryStore()
	id, err := store.Set("", map[string]interface{}{"sub": "alice"})
	require.Nil(t, err)
	assert.NotEmpty(t, id)

	claims, ok := store.Get(id)
	require.True(t, ok)
	assert.Equal(t, "alice", claims["sub"])
}

func TestMemoryStore_SetWithID(t *testing.T) {
	store := NewMemoryStore()
	id, err := store.Set("custom-id", map[string]interface{}{"sub": "bob"})
	require.Nil(t, err)
	assert.Equal(t, "custom-id", id)

	claims, ok := store.Get("custom-id")
	require.True(t, ok)
	assert.Equal(t, "bob", claims["sub"])
}

func TestMemoryStore_GetMissing(t *testing.T) {
	store := NewMemoryStore()
	_, ok := store.Get("nonexistent")
	assert.False(t, ok)
}

func TestMemoryStore_Delete(t *testing.T) {
	store := NewMemoryStore()
	id, _ := store.Set("", map[string]interface{}{"sub": "alice"})
	store.Delete(id)
	_, ok := store.Get(id)
	assert.False(t, ok)
}

// ---------------------------------------------------------------------------
// AuthenticateToken
// ---------------------------------------------------------------------------

func TestAuthenticateToken_Valid(t *testing.T) {
	store := NewMemoryStore()
	id, _ := store.Set("", map[string]interface{}{engine.ClaimFieldSubject: "alice"})

	auth, _ := NewAuthenticator(WithStore(store))
	claims, err := auth.AuthenticateToken(id)
	require.Nil(t, err)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "alice", sub)
}

func TestAuthenticateToken_Invalid(t *testing.T) {
	store := NewMemoryStore()
	auth, _ := NewAuthenticator(WithStore(store))
	_, err := auth.AuthenticateToken("nonexistent")
	assert.Equal(t, engine.ErrUnauthenticated, err)
}

func TestAuthenticateToken_Empty(t *testing.T) {
	auth, _ := NewAuthenticator(WithStore(NewMemoryStore()))
	_, err := auth.AuthenticateToken("")
	assert.Equal(t, engine.ErrMissingBearerToken, err)
}

// ---------------------------------------------------------------------------
// Authenticate (via context)
// ---------------------------------------------------------------------------

func TestAuthenticate_Success(t *testing.T) {
	store := NewMemoryStore()
	id, _ := store.Set("", map[string]interface{}{engine.ClaimFieldSubject: "alice"})

	auth, _ := NewAuthenticator(WithStore(store))
	ctx := ContextWithSessionID(context.Background(), id)
	claims, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	require.Nil(t, err)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "alice", sub)
}

func TestAuthenticate_MissingSessionID(t *testing.T) {
	auth, _ := NewAuthenticator(WithStore(NewMemoryStore()))
	_, err := auth.Authenticate(context.Background(), engine.ContextTypeGrpc)
	assert.Equal(t, engine.ErrMissingBearerToken, err)
}

func TestAuthenticate_EmptySessionID(t *testing.T) {
	auth, _ := NewAuthenticator(WithStore(NewMemoryStore()))
	ctx := ContextWithSessionID(context.Background(), "")
	_, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	assert.Equal(t, engine.ErrMissingBearerToken, err)
}

func TestAuthenticate_InvalidSessionID(t *testing.T) {
	auth, _ := NewAuthenticator(WithStore(NewMemoryStore()))
	ctx := ContextWithSessionID(context.Background(), "nonexistent")
	_, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	assert.Equal(t, engine.ErrUnauthenticated, err)
}

// ---------------------------------------------------------------------------
// CreateIdentity
// ---------------------------------------------------------------------------

func TestCreateIdentity_Success(t *testing.T) {
	store := NewMemoryStore()
	auth, _ := NewAuthenticator(WithStore(store))
	claims := engine.AuthClaims{engine.ClaimFieldSubject: "alice"}
	sessionID, err := auth.CreateIdentity(claims)
	require.Nil(t, err)
	assert.NotEmpty(t, sessionID)

	// The created session should be authenticatable
	decoded, err := auth.AuthenticateToken(sessionID)
	require.Nil(t, err)
	sub, _ := decoded.GetSubject()
	assert.Equal(t, "alice", sub)
}

func TestCreateIdentityWithContext_Success(t *testing.T) {
	store := NewMemoryStore()
	auth, _ := NewAuthenticator(WithStore(store))
	claims := engine.AuthClaims{engine.ClaimFieldSubject: "alice"}
	ctx, err := auth.CreateIdentityWithContext(context.Background(), engine.ContextTypeGrpc, claims)
	require.Nil(t, err)

	// Verify session ID is in context
	sessionID, ok := SessionIDFromContext(ctx)
	require.True(t, ok)
	assert.NotEmpty(t, sessionID)

	// Verify it can be authenticated via context
	decoded, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	require.Nil(t, err)
	sub, _ := decoded.GetSubject()
	assert.Equal(t, "alice", sub)
}

// ---------------------------------------------------------------------------
// Context helpers
// ---------------------------------------------------------------------------

func TestSessionIDFromContext_Missing(t *testing.T) {
	_, ok := SessionIDFromContext(context.Background())
	assert.False(t, ok)
}

// ---------------------------------------------------------------------------
// Close / interface compliance
// ---------------------------------------------------------------------------

func TestClose_NoError(t *testing.T) {
	auth, _ := NewAuthenticator(WithStore(NewMemoryStore()))
	auth.Close()
}

func TestInterfaceCompliance(t *testing.T) {
	var _ engine.Authenticator = (*Authenticator)(nil)
}
