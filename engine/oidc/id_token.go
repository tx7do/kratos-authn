package oidc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"time"

	"github.com/tx7do/kratos-authn/engine"
)

// IDToken is an OpenID Connect extension that provides a predictable representation
// of an authorization event.
//
// The ID Token only holds fields OpenID Connect requires. To access additional
// claims returned by the server, use the Claims method.
type IDToken struct {
	// The URL of the server which issued this token. OpenID Connect
	// requires this value always be identical to the URL used for
	// initial discovery.
	//
	// Note: Because of a known issue with Google Accounts' implementation
	// this value may differ when using Google.
	//
	// See: https://developers.google.com/identity/protocols/OpenIDConnect#obtainuserinfo
	Issuer string

	// The client ID, or set of client IDs, that this token is issued for. For
	// common uses, this is the client that initialized the auth flow.
	//
	// This package ensures the audience contains an expected value.
	Audience []string

	// A unique string which identifies the end user.
	Subject string

	// Expiry of the token. Ths package will not process tokens that have
	// expired unless that validation is explicitly turned off.
	Expiry time.Time
	// When the token was issued by the provider.
	IssuedAt time.Time

	// Initial nonce provided during the authentication redirect.
	//
	// This package does NOT provide verification on the value of this field,
	// and it's the user's responsibility to ensure it contains a valid value.
	Nonce string

	// at_hash claim, if set in the ID token. Callers can verify an access token
	// that corresponds to the ID token using the VerifyAccessToken method.
	AccessTokenHash string

	// signature algorithm used for ID token, needed to compute a verification hash of an
	// access token
	sigAlgorithm string

	// Raw payload of the id_token.
	claims []byte

	// Map of distributed claim names to claim sources
	distributedClaims map[string]claimSource
}

// Claims unmarshal the raw JSON payload of the ID Token into a provided struct.
//
//	idToken, err := idTokenVerifier.Verify(rawIDToken)
//	if err != nil {
//		// handle error
//	}
//	var claims struct {
//		Email         string `json:"email"`
//		EmailVerified bool   `json:"email_verified"`
//	}
//	if err := idToken.Claims(&claims); err != nil {
//		// handle error
//	}
func (i *IDToken) Claims(v interface{}) error {
	if i.claims == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(i.claims, v)
}

// VerifyAccessToken verifies that the hash of the access token that corresponds to the iD token
// matches the hash in the id token. It returns an error if the hashes  don't match.
// It is the caller's responsibility to ensure that the optional access token hash is present for the ID token
// before calling this method. See https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
func (i *IDToken) VerifyAccessToken(accessToken string) error {
	if i.AccessTokenHash == "" {
		return engine.ErrNoAtHash
	}
	var h hash.Hash
	switch i.sigAlgorithm {
	case RS256, ES256, PS256:
		h = sha256.New()
	case RS384, ES384, PS384:
		h = sha512.New384()
	case RS512, ES512, PS512:
		h = sha512.New()
	default:
		return fmt.Errorf("oidc: unsupported signing algorithm %q", i.sigAlgorithm)
	}
	h.Write([]byte(accessToken)) // hash documents that Write will never return an error
	sum := h.Sum(nil)[:h.Size()/2]
	actual := base64.RawURLEncoding.EncodeToString(sum)
	if actual != i.AccessTokenHash {
		return engine.ErrInvalidAtHash
	}
	return nil
}
