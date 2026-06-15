// Package hmac implements an [engine.Authenticator] that validates
// HMAC-SHA256 request signatures.
//
// The signature is transmitted as a Bearer token containing a
// dot-separated payload:
//
//	Authorization: Bearer <keyID>.<timestamp>.<signature>
//
// Where signature = HMAC-SHA256(secret, "keyID.timestamp").
//
// The authenticator:
//  1. Parses the token into keyID, timestamp, and signature.
//  2. Resolves the secret for the keyID.
//  3. Recomputes the HMAC and compares.
//  4. Validates the timestamp against the allowed clock skew.
package hmac

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/tx7do/kratos-authn/engine"
)

// Authenticator validates HMAC-SHA256 signatures.
type Authenticator struct {
	options *Options
}

var _ engine.Authenticator = (*Authenticator)(nil)

// NewAuthenticator creates an HMAC authenticator from the given options.
func NewAuthenticator(opts ...Option) (engine.Authenticator, error) {
	o := &Options{}
	for _, opt := range opts {
		opt(o)
	}
	return &Authenticator{options: o}, nil
}

// Authenticate extracts the HMAC token from the incoming metadata and validates it.
func (a *Authenticator) Authenticate(ctx context.Context, contextType engine.ContextType) (*engine.AuthClaims, error) {
	tokenString, err := engine.AuthFromMD(ctx, engine.BearerWord, contextType)
	if err != nil {
		return nil, engine.ErrMissingBearerToken
	}
	return a.AuthenticateToken(tokenString)
}

// AuthenticateToken parses and validates an HMAC token of the form
// "keyID.timestamp.signature".
func (a *Authenticator) AuthenticateToken(token string) (*engine.AuthClaims, error) {
	keyID, timestamp, signature, err := parseHMACToken(token)
	if err != nil {
		return nil, engine.ErrInvalidToken
	}

	// Validate timestamp freshness.
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return nil, engine.ErrInvalidToken
	}

	now := time.Now().Unix()
	skew := int64(a.options.getMaxSkew().Seconds())
	if now-ts > skew || ts-now > skew {
		return nil, engine.ErrTokenExpired
	}

	// Resolve the secret.
	secret, ok := a.options.getSecret(keyID)
	if !ok {
		return nil, engine.ErrUnauthenticated
	}

	// Recompute HMAC.
	expectedSig := computeHMAC(secret, keyID, timestamp)
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return nil, engine.ErrUnauthenticated
	}

	return &engine.AuthClaims{
		engine.ClaimFieldSubject: keyID,
	}, nil
}

// CreateIdentityWithContext injects the HMAC token into the outgoing metadata.
func (a *Authenticator) CreateIdentityWithContext(ctx context.Context, contextType engine.ContextType, claims engine.AuthClaims) (context.Context, error) {
	token, err := a.CreateIdentity(claims)
	if err != nil {
		return ctx, err
	}
	if token == "" {
		return ctx, nil
	}
	ctx = engine.MDWithAuth(ctx, engine.BearerWord, token, contextType)
	return ctx, nil
}

// CreateIdentity generates an HMAC token for the given subject (keyID).
func (a *Authenticator) CreateIdentity(claims engine.AuthClaims) (string, error) {
	keyID, _ := claims.GetSubject()
	if keyID == "" {
		return "", errors.New("subject (keyID) is required")
	}

	secret, ok := a.options.getSecret(keyID)
	if !ok {
		return "", errors.New("no secret configured for keyID")
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	sig := computeHMAC(secret, keyID, timestamp)
	return keyID + "." + timestamp + "." + sig, nil
}

func (a *Authenticator) Close() {}

// parseHMACToken splits "keyID.timestamp.signature".
func parseHMACToken(token string) (keyID, timestamp, signature string, err error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", "", "", errors.New("invalid HMAC token format")
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", errors.New("invalid HMAC token: empty component")
	}
	return parts[0], parts[1], parts[2], nil
}

// computeHMAC returns the hex-encoded HMAC-SHA256(secret, "keyID.timestamp").
func computeHMAC(secret, keyID, timestamp string) string {
	msg := keyID + "." + timestamp
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(msg))
	return hex.EncodeToString(h.Sum(nil))
}
