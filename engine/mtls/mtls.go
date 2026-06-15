// Package mtls implements an [engine.Authenticator] that validates
// client identities based on mutual TLS (mTLS) client certificates.
//
// Unlike Bearer-token authenticators, mTLS does not use the Authorization
// header. Instead, the client certificate is extracted from the TLS
// connection state and its Subject Common Name (or SAN) is used as the
// identity.
//
// The HTTP middleware or gRPC interceptor must inject the peer certificate
// subject into the request context via [ContextWithPeerSubject] before
// calling Authenticate.
//
// Usage:
//
//	auth, _ := mtls.NewAuthenticator(mtls.WithTrustedCN("svc-1"))
//	// In HTTP middleware:
//	ctx = mtls.ContextWithPeerSubject(r.Context(), r.TLS.PeerCertificates[0].Subject.CommonName)
//	claims, err := auth.Authenticate(ctx)
package mtls

import (
	"context"
	"crypto/x509"

	"github.com/tx7do/kratos-authn/engine"
)

// context key type for mTLS peer certificate info.
type ctxKey string

const (
	peerSubjectKey ctxKey = "mtls-peer-subject"
	peerCertKey    ctxKey = "mtls-peer-cert"
)

// ContextWithPeerSubject injects the client certificate subject (CN or SAN)
// into the context.
func ContextWithPeerSubject(parent context.Context, subject string) context.Context {
	return context.WithValue(parent, peerSubjectKey, subject)
}

// PeerSubjectFromContext extracts the peer subject from the context.
func PeerSubjectFromContext(ctx context.Context) (string, bool) {
	sub, ok := ctx.Value(peerSubjectKey).(string)
	return sub, ok
}

// ContextWithPeerCert injects the full client certificate into the context.
func ContextWithPeerCert(parent context.Context, cert *x509.Certificate) context.Context {
	return context.WithValue(parent, peerCertKey, cert)
}

// PeerCertFromContext extracts the peer certificate from the context.
func PeerCertFromContext(ctx context.Context) (*x509.Certificate, bool) {
	cert, ok := ctx.Value(peerCertKey).(*x509.Certificate)
	return cert, ok
}

// Authenticator validates mTLS client certificates.
type Authenticator struct {
	options *Options
}

var _ engine.Authenticator = (*Authenticator)(nil)

// NewAuthenticator creates an mTLS authenticator from the given options.
func NewAuthenticator(opts ...Option) (engine.Authenticator, error) {
	o := &Options{}
	for _, opt := range opts {
		opt(o)
	}
	return &Authenticator{options: o}, nil
}

// Authenticate validates the peer certificate subject from the context.
// The Bearer token mechanism is not used — identity comes from the TLS layer.
func (a *Authenticator) Authenticate(ctx context.Context, _ engine.ContextType) (*engine.AuthClaims, error) {
	subject, ok := PeerSubjectFromContext(ctx)
	if !ok || subject == "" {
		return nil, engine.ErrMissingBearerToken
	}
	return a.authenticateSubject(subject)
}

// AuthenticateToken validates a subject string directly (useful for testing
// and integration scenarios where the subject is already extracted).
func (a *Authenticator) AuthenticateToken(token string) (*engine.AuthClaims, error) {
	if token == "" {
		return nil, engine.ErrMissingBearerToken
	}
	return a.authenticateSubject(token)
}

func (a *Authenticator) authenticateSubject(subject string) (*engine.AuthClaims, error) {
	// Validator takes precedence.
	if a.options.validator != nil {
		claims, valid := a.options.validator(subject)
		if !valid {
			return nil, engine.ErrUnauthenticated
		}
		c := engine.AuthClaims(claims)
		return &c, nil
	}

	// Static CN check.
	if !a.options.isTrusted(subject) {
		return nil, engine.ErrUnauthenticated
	}

	return &engine.AuthClaims{
		engine.ClaimFieldSubject: subject,
	}, nil
}

// CreateIdentityWithContext injects the peer subject into the context.
func (a *Authenticator) CreateIdentityWithContext(ctx context.Context, _ engine.ContextType, claims engine.AuthClaims) (context.Context, error) {
	subject, _ := claims.GetSubject()
	if subject != "" {
		ctx = ContextWithPeerSubject(ctx, subject)
	}
	return ctx, nil
}

// CreateIdentity returns the subject from claims.
func (a *Authenticator) CreateIdentity(claims engine.AuthClaims) (string, error) {
	sub, _ := claims.GetSubject()
	return sub, nil
}

func (a *Authenticator) Close() {}
