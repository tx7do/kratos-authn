package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	engine "github.com/tx7do/kratos-authn/engine"
)

// ---------------------------------------------------------------------------
// mock introspection server
// ---------------------------------------------------------------------------

func newMockIntrospectionServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		token := r.FormValue("token")

		switch token {
		case "valid-token":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"active":     true,
				"scope":      "read write",
				"client_id":  "my-client",
				"username":   "alice",
				"token_type": "Bearer",
				"exp":        9999999999,
				"sub":        "user-123",
				"iss":        "https://idp.example.com",
				"custom":     "custom-value",
			})
		case "expired-token":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"active": false,
			})
		default:
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token"})
		}
	}))
}

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

func TestNewAuthenticator_Success(t *testing.T) {
	auth, err := NewAuthenticator(WithIntrospectURL("http://localhost/introspect"))
	require.Nil(t, err)
	require.NotNil(t, auth)
}

func TestNewAuthenticator_MissingURL(t *testing.T) {
	_, err := NewAuthenticator()
	assert.NotNil(t, err)
}

func TestNewAuthenticator_WithClientCredentials(t *testing.T) {
	auth, err := NewAuthenticator(
		WithIntrospectURL("http://localhost/introspect"),
		WithClientCredentials("cid", "csecret"),
	)
	require.Nil(t, err)
	require.NotNil(t, auth)
}

// ---------------------------------------------------------------------------
// AuthenticateToken
// ---------------------------------------------------------------------------

func TestAuthenticateToken_Valid(t *testing.T) {
	srv := newMockIntrospectionServer()
	defer srv.Close()

	auth, _ := NewAuthenticator(
		WithIntrospectURL(srv.URL),
		WithExtraClaimsKeys("custom"),
	)
	claims, err := auth.AuthenticateToken("valid-token")
	require.Nil(t, err)

	sub, _ := claims.GetSubject()
	assert.Equal(t, "user-123", sub)

	scopes, _ := claims.GetScopes()
	assert.Equal(t, []string{"read", "write"}, []string(scopes))

	issuer, _ := claims.GetIssuer()
	assert.Equal(t, "https://idp.example.com", issuer)

	// extra claim
	assert.Equal(t, "custom-value", (*claims)["custom"])
}

func TestAuthenticateToken_InactiveToken(t *testing.T) {
	srv := newMockIntrospectionServer()
	defer srv.Close()

	auth, _ := NewAuthenticator(WithIntrospectURL(srv.URL))
	_, err := auth.AuthenticateToken("expired-token")
	assert.Equal(t, engine.ErrUnauthenticated, err)
}

func TestAuthenticateToken_UnknownToken(t *testing.T) {
	srv := newMockIntrospectionServer()
	defer srv.Close()

	auth, _ := NewAuthenticator(WithIntrospectURL(srv.URL))
	_, err := auth.AuthenticateToken("unknown")
	assert.NotNil(t, err)
}

func TestAuthenticateToken_ServerError(t *testing.T) {
	auth, _ := NewAuthenticator(WithIntrospectURL("http://127.0.0.1:0/introspect"))
	_, err := auth.AuthenticateToken("any-token")
	assert.NotNil(t, err)
}

// ---------------------------------------------------------------------------
// Authenticate (via gRPC context)
// ---------------------------------------------------------------------------

func TestAuthenticate_Success(t *testing.T) {
	srv := newMockIntrospectionServer()
	defer srv.Close()

	auth, _ := NewAuthenticator(WithIntrospectURL(srv.URL))
	ctx := createAuthCtx("valid-token")
	claims, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	require.Nil(t, err)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "user-123", sub)
}

func TestAuthenticate_MissingToken(t *testing.T) {
	srv := newMockIntrospectionServer()
	defer srv.Close()

	auth, _ := NewAuthenticator(WithIntrospectURL(srv.URL))
	_, err := auth.Authenticate(context.Background(), engine.ContextTypeGrpc)
	assert.Equal(t, engine.ErrMissingBearerToken, err)
}

func TestAuthenticate_InactiveToken(t *testing.T) {
	srv := newMockIntrospectionServer()
	defer srv.Close()

	auth, _ := NewAuthenticator(WithIntrospectURL(srv.URL))
	ctx := createAuthCtx("expired-token")
	_, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	assert.Equal(t, engine.ErrUnauthenticated, err)
}

// ---------------------------------------------------------------------------
// Client credentials
// ---------------------------------------------------------------------------

func TestAuthenticateToken_WithClientCredentials(t *testing.T) {
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		_ = r.ParseForm()
		if r.FormValue("token") == "valid-token" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"active": true,
				"sub":    "user-456",
			})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{"active": false})
		}
	}))
	defer srv.Close()

	auth, _ := NewAuthenticator(
		WithIntrospectURL(srv.URL),
		WithClientCredentials("cid", "csecret"),
	)
	_, err := auth.AuthenticateToken("valid-token")
	require.Nil(t, err)

	// verify Basic auth header was sent
	assert.True(t, strings.HasPrefix(capturedAuth, "Basic "))
}

// ---------------------------------------------------------------------------
// CreateIdentity
// ---------------------------------------------------------------------------

func TestCreateIdentity_Success(t *testing.T) {
	srv := newMockIntrospectionServer()
	defer srv.Close()

	auth, _ := NewAuthenticator(WithIntrospectURL(srv.URL))
	claims := engine.AuthClaims{engine.ClaimFieldSubject: "some-sub"}
	token, err := auth.CreateIdentity(claims)
	require.Nil(t, err)
	assert.Equal(t, "some-sub", token)
}

func TestCreateIdentityWithContext_Success(t *testing.T) {
	srv := newMockIntrospectionServer()
	defer srv.Close()

	auth, _ := NewAuthenticator(WithIntrospectURL(srv.URL))
	claims := engine.AuthClaims{engine.ClaimFieldSubject: "some-sub"}
	ctx, err := auth.CreateIdentityWithContext(context.Background(), engine.ContextTypeGrpc, claims)
	require.Nil(t, err)
	require.NotNil(t, ctx)
}

// ---------------------------------------------------------------------------
// Close / interface compliance
// ---------------------------------------------------------------------------

func TestClose_NoError(t *testing.T) {
	srv := newMockIntrospectionServer()
	defer srv.Close()

	auth, _ := NewAuthenticator(WithIntrospectURL(srv.URL))
	auth.Close()
}

func TestInterfaceCompliance(t *testing.T) {
	var _ engine.Authenticator = (*Authenticator)(nil)
}
