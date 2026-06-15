package hmac

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

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

// generateToken creates a valid HMAC token for testing.
func generateToken(keyID, secret string, ts int64) string {
	timestamp := strconv.FormatInt(ts, 10)
	sig := computeHMAC(secret, keyID, timestamp)
	return keyID + "." + timestamp + "." + sig
}

func computeSig(secret, keyID, timestamp string) string {
	msg := keyID + "." + timestamp
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(msg))
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// NewAuthenticator / Options
// ---------------------------------------------------------------------------

func TestNewAuthenticator_WithSecret(t *testing.T) {
	auth, err := NewAuthenticator(WithSecret("key-1", "super-secret"))
	require.Nil(t, err)
	require.NotNil(t, auth)
}

func TestNewAuthenticator_WithSecrets(t *testing.T) {
	auth, err := NewAuthenticator(WithSecrets(map[string]string{
		"key-1": "secret-1",
		"key-2": "secret-2",
	}))
	require.Nil(t, err)
	require.NotNil(t, auth)
}

func TestNewAuthenticator_WithResolver(t *testing.T) {
	auth, err := NewAuthenticator(WithSecretResolver(func(keyID string) (string, bool) {
		if keyID == "key-1" {
			return "resolved-secret", true
		}
		return "", false
	}))
	require.Nil(t, err)
	require.NotNil(t, auth)
}

func TestNewAuthenticator_WithMaxSkew(t *testing.T) {
	auth, err := NewAuthenticator(WithSecret("k", "s"), WithMaxSkew(10*time.Minute))
	require.Nil(t, err)
	require.NotNil(t, auth)
}

// ---------------------------------------------------------------------------
// AuthenticateToken
// ---------------------------------------------------------------------------

func TestAuthenticateToken_Valid_StaticSecret(t *testing.T) {
	auth, _ := NewAuthenticator(WithSecret("key-1", "super-secret"))
	now := time.Now().Unix()
	token := generateToken("key-1", "super-secret", now)

	claims, err := auth.AuthenticateToken(token)
	require.Nil(t, err)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "key-1", sub)
}

func TestAuthenticateToken_Valid_Resolver(t *testing.T) {
	auth, _ := NewAuthenticator(WithSecretResolver(func(keyID string) (string, bool) {
		if keyID == "key-1" {
			return "resolved-secret", true
		}
		return "", false
	}))
	now := time.Now().Unix()
	token := generateToken("key-1", "resolved-secret", now)

	claims, err := auth.AuthenticateToken(token)
	require.Nil(t, err)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "key-1", sub)
}

func TestAuthenticateToken_InvalidFormat(t *testing.T) {
	auth, _ := NewAuthenticator(WithSecret("key-1", "super-secret"))
	_, err := auth.AuthenticateToken("just-a-string")
	assert.Equal(t, engine.ErrInvalidToken, err)
}

func TestAuthenticateToken_EmptyComponent(t *testing.T) {
	auth, _ := NewAuthenticator(WithSecret("key-1", "super-secret"))
	_, err := auth.AuthenticateToken("..")
	assert.Equal(t, engine.ErrInvalidToken, err)
}

func TestAuthenticateToken_BadSignature(t *testing.T) {
	auth, _ := NewAuthenticator(WithSecret("key-1", "super-secret"))
	now := time.Now().Unix()
	timestamp := strconv.FormatInt(now, 10)
	token := "key-1." + timestamp + ".badsignature"
	_, err := auth.AuthenticateToken(token)
	assert.Equal(t, engine.ErrUnauthenticated, err)
}

func TestAuthenticateToken_UnknownKeyID(t *testing.T) {
	auth, _ := NewAuthenticator(WithSecret("key-1", "super-secret"))
	now := time.Now().Unix()
	token := generateToken("unknown-key", "some-secret", now)
	_, err := auth.AuthenticateToken(token)
	assert.Equal(t, engine.ErrUnauthenticated, err)
}

func TestAuthenticateToken_ExpiredTimestamp(t *testing.T) {
	auth, _ := NewAuthenticator(WithSecret("key-1", "super-secret"), WithMaxSkew(1*time.Minute))
	old := time.Now().Unix() - 3600 // 1 hour ago
	token := generateToken("key-1", "super-secret", old)
	_, err := auth.AuthenticateToken(token)
	assert.Equal(t, engine.ErrTokenExpired, err)
}

func TestAuthenticateToken_FutureTimestamp(t *testing.T) {
	auth, _ := NewAuthenticator(WithSecret("key-1", "super-secret"), WithMaxSkew(1*time.Minute))
	future := time.Now().Unix() + 3600
	token := generateToken("key-1", "super-secret", future)
	_, err := auth.AuthenticateToken(token)
	assert.Equal(t, engine.ErrTokenExpired, err)
}

func TestAuthenticateToken_InvalidTimestamp(t *testing.T) {
	auth, _ := NewAuthenticator(WithSecret("key-1", "super-secret"))
	token := "key-1.not-a-number." + computeSig("super-secret", "key-1", "not-a-number")
	_, err := auth.AuthenticateToken(token)
	assert.Equal(t, engine.ErrInvalidToken, err)
}

// ---------------------------------------------------------------------------
// Authenticate (via gRPC context)
// ---------------------------------------------------------------------------

func TestAuthenticate_Success(t *testing.T) {
	auth, _ := NewAuthenticator(WithSecret("key-1", "super-secret"))
	now := time.Now().Unix()
	token := generateToken("key-1", "super-secret", now)
	ctx := createAuthCtx(token)

	claims, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	require.Nil(t, err)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "key-1", sub)
}

func TestAuthenticate_MissingToken(t *testing.T) {
	auth, _ := NewAuthenticator(WithSecret("key-1", "super-secret"))
	_, err := auth.Authenticate(context.Background(), engine.ContextTypeGrpc)
	assert.Equal(t, engine.ErrMissingBearerToken, err)
}

// ---------------------------------------------------------------------------
// CreateIdentity
// ---------------------------------------------------------------------------

func TestCreateIdentity_Success(t *testing.T) {
	auth, _ := NewAuthenticator(WithSecret("key-1", "super-secret"))
	claims := engine.AuthClaims{engine.ClaimFieldSubject: "key-1"}
	token, err := auth.CreateIdentity(claims)
	require.Nil(t, err)
	assert.NotEmpty(t, token)

	// the generated token should authenticate
	decoded, err := auth.AuthenticateToken(token)
	require.Nil(t, err)
	sub, _ := decoded.GetSubject()
	assert.Equal(t, "key-1", sub)
}

func TestCreateIdentity_NoSubject(t *testing.T) {
	auth, _ := NewAuthenticator(WithSecret("key-1", "super-secret"))
	_, err := auth.CreateIdentity(engine.AuthClaims{})
	assert.NotNil(t, err)
}

func TestCreateIdentity_NoSecret(t *testing.T) {
	auth, _ := NewAuthenticator()
	claims := engine.AuthClaims{engine.ClaimFieldSubject: "key-1"}
	_, err := auth.CreateIdentity(claims)
	assert.NotNil(t, err)
}

func TestCreateIdentityWithContext_Success(t *testing.T) {
	auth, _ := NewAuthenticator(WithSecret("key-1", "super-secret"))
	claims := engine.AuthClaims{engine.ClaimFieldSubject: "key-1"}
	ctx, err := auth.CreateIdentityWithContext(context.Background(), engine.ContextTypeGrpc, claims)
	require.Nil(t, err)
	require.NotNil(t, ctx)
}

// ---------------------------------------------------------------------------
// Close / interface compliance
// ---------------------------------------------------------------------------

func TestClose_NoError(t *testing.T) {
	auth, _ := NewAuthenticator(WithSecret("key-1", "super-secret"))
	auth.Close()
}

func TestInterfaceCompliance(t *testing.T) {
	var _ engine.Authenticator = (*Authenticator)(nil)
}
