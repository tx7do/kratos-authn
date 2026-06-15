package mtls

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	engine "github.com/tx7do/kratos-authn/engine"
)

// ---------------------------------------------------------------------------
// NewAuthenticator / Options
// ---------------------------------------------------------------------------

func TestNewAuthenticator_NoRestriction(t *testing.T) {
	auth, err := NewAuthenticator()
	require.Nil(t, err)
	require.NotNil(t, auth)
}

func TestNewAuthenticator_WithTrustedCN(t *testing.T) {
	auth, err := NewAuthenticator(WithTrustedCN("svc-1"))
	require.Nil(t, err)
	require.NotNil(t, auth)
}

func TestNewAuthenticator_WithTrustedCNs(t *testing.T) {
	auth, err := NewAuthenticator(WithTrustedCNs([]string{"svc-1", "svc-2"}))
	require.Nil(t, err)
	require.NotNil(t, auth)
}

func TestNewAuthenticator_WithValidator(t *testing.T) {
	auth, err := NewAuthenticator(WithValidator(func(sub string) (map[string]interface{}, bool) {
		return map[string]interface{}{engine.ClaimFieldSubject: sub}, true
	}))
	require.Nil(t, err)
	require.NotNil(t, auth)
}

// ---------------------------------------------------------------------------
// Authenticate (via context)
// ---------------------------------------------------------------------------

func TestAuthenticate_Success_NoRestriction(t *testing.T) {
	auth, _ := NewAuthenticator()
	ctx := ContextWithPeerSubject(context.Background(), "any-client")
	claims, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	require.Nil(t, err)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "any-client", sub)
}

func TestAuthenticate_Success_TrustedCN(t *testing.T) {
	auth, _ := NewAuthenticator(WithTrustedCN("svc-1"))
	ctx := ContextWithPeerSubject(context.Background(), "svc-1")
	claims, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	require.Nil(t, err)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "svc-1", sub)
}

func TestAuthenticate_Success_Validator(t *testing.T) {
	auth, _ := NewAuthenticator(WithValidator(func(sub string) (map[string]interface{}, bool) {
		if sub == "svc-1" {
			return map[string]interface{}{
				engine.ClaimFieldSubject: "svc-1",
				"role":                   "admin",
			}, true
		}
		return nil, false
	}))
	ctx := ContextWithPeerSubject(context.Background(), "svc-1")
	claims, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	require.Nil(t, err)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "svc-1", sub)
	assert.Equal(t, "admin", (*claims)["role"])
}

func TestAuthenticate_UntrustedCN(t *testing.T) {
	auth, _ := NewAuthenticator(WithTrustedCN("svc-1"))
	ctx := ContextWithPeerSubject(context.Background(), "unknown-client")
	_, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	assert.Equal(t, engine.ErrUnauthenticated, err)
}

func TestAuthenticate_ValidatorRejects(t *testing.T) {
	auth, _ := NewAuthenticator(WithValidator(func(sub string) (map[string]interface{}, bool) {
		return nil, false
	}))
	ctx := ContextWithPeerSubject(context.Background(), "any-client")
	_, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	assert.Equal(t, engine.ErrUnauthenticated, err)
}

func TestAuthenticate_NoPeerSubject(t *testing.T) {
	auth, _ := NewAuthenticator()
	_, err := auth.Authenticate(context.Background(), engine.ContextTypeGrpc)
	assert.Equal(t, engine.ErrMissingBearerToken, err)
}

func TestAuthenticate_EmptyPeerSubject(t *testing.T) {
	auth, _ := NewAuthenticator()
	ctx := ContextWithPeerSubject(context.Background(), "")
	_, err := auth.Authenticate(ctx, engine.ContextTypeGrpc)
	assert.Equal(t, engine.ErrMissingBearerToken, err)
}

// ---------------------------------------------------------------------------
// AuthenticateToken
// ---------------------------------------------------------------------------

func TestAuthenticateToken_Success(t *testing.T) {
	auth, _ := NewAuthenticator(WithTrustedCN("svc-1"))
	claims, err := auth.AuthenticateToken("svc-1")
	require.Nil(t, err)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "svc-1", sub)
}

func TestAuthenticateToken_Empty(t *testing.T) {
	auth, _ := NewAuthenticator()
	_, err := auth.AuthenticateToken("")
	assert.Equal(t, engine.ErrMissingBearerToken, err)
}

// ---------------------------------------------------------------------------
// PeerCert context helpers
// ---------------------------------------------------------------------------

func TestContextWithPeerCert(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "test-cn"},
	}
	ctx := ContextWithPeerCert(context.Background(), cert)

	extracted, ok := PeerCertFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "test-cn", extracted.Subject.CommonName)
}

func TestPeerCertFromContext_Missing(t *testing.T) {
	_, ok := PeerCertFromContext(context.Background())
	assert.False(t, ok)
}

func TestPeerSubjectFromContext_Missing(t *testing.T) {
	_, ok := PeerSubjectFromContext(context.Background())
	assert.False(t, ok)
}

// ---------------------------------------------------------------------------
// CreateIdentity
// ---------------------------------------------------------------------------

func TestCreateIdentity_Success(t *testing.T) {
	auth, _ := NewAuthenticator()
	claims := engine.AuthClaims{engine.ClaimFieldSubject: "svc-1"}
	token, err := auth.CreateIdentity(claims)
	require.Nil(t, err)
	assert.Equal(t, "svc-1", token)
}

func TestCreateIdentityWithContext_Success(t *testing.T) {
	auth, _ := NewAuthenticator()
	claims := engine.AuthClaims{engine.ClaimFieldSubject: "svc-1"}
	ctx, err := auth.CreateIdentityWithContext(context.Background(), engine.ContextTypeGrpc, claims)
	require.Nil(t, err)

	subject, ok := PeerSubjectFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "svc-1", subject)
}

// ---------------------------------------------------------------------------
// Close / interface compliance
// ---------------------------------------------------------------------------

func TestClose_NoError(t *testing.T) {
	auth, _ := NewAuthenticator()
	auth.Close()
}

func TestInterfaceCompliance(t *testing.T) {
	var _ engine.Authenticator = (*Authenticator)(nil)
}
