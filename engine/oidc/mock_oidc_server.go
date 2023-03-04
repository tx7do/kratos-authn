package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type mockOidcServer struct {
	issuerURL  string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

const kidHeader = "1"

func NewMockOidcServer(issuerURL string) (*mockOidcServer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	mockServer := &mockOidcServer{
		issuerURL:  issuerURL,
		privateKey: privateKey,
		publicKey:  privateKey.Public().(*rsa.PublicKey),
	}

	mockServer.start()
	return mockServer, nil
}

func (server mockOidcServer) start() {
	http.HandleFunc("/.well-known/openid-configuration", server.handleGetConfiguration)
	http.HandleFunc("/oidc/jwks", server.handleGetJWKS)
	http.HandleFunc("/oauth2/token", server.handleGetToken)
	http.HandleFunc("/oidc/userinfo", server.handleGetUserInfo)

	port := strings.Split(server.issuerURL, ":")[2]
	go func() {
		log.Fatal(http.ListenAndServe(":"+port, nil))
	}()
}

func (server mockOidcServer) handleGetConfiguration(w http.ResponseWriter, r *http.Request) {
	err := json.NewEncoder(w).Encode(map[string]string{
		"issuer":                 server.issuerURL,
		"jwks_uri":               fmt.Sprintf("%s/oidc/jwks", server.issuerURL),
		"revocation_endpoint":    fmt.Sprintf("%s/oauth2/revoke", server.issuerURL),
		"token_endpoint":         fmt.Sprintf("%s/oauth2/token", server.issuerURL),
		"authorization_endpoint": fmt.Sprintf("%s/oidc/authorize", server.issuerURL),
		"userinfo_endpoint":      fmt.Sprintf("%s/oidc/userinfo", server.issuerURL),
	})
	if err != nil {
		log.Fatalf("failed to json encode the openid configurations: %v", err)
	}
}

func (server mockOidcServer) handleGetJWKS(w http.ResponseWriter, r *http.Request) {
	err := json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": []map[string]string{
			{
				"kid": kidHeader,
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(server.publicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(server.publicKey.E)).Bytes()),
			},
		},
	})
	if err != nil {
		log.Fatalf("failed to json encode the jwks keys: %v", err)
	}
}

func (server mockOidcServer) handleGetToken(w http.ResponseWriter, r *http.Request) {
	var err error
	token, err := server.GetToken("kratos.dev", "user")

	err = json.NewEncoder(w).Encode(map[string]string{
		"token_type":    "Bearer",
		"expires_in":    "3600",
		"access_token":  "8xLOxBtZp8",
		"refresh_token": "8xLOxBtZp8",
		"id_token":      token,
	})
	if err != nil {
		log.Fatalf("failed to json encode the openid configurations: %v", err)
	}
}

func (server mockOidcServer) handleGetUserInfo(w http.ResponseWriter, r *http.Request) {

}

func (server mockOidcServer) GetToken(audience, subject string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:   server.issuerURL,
		Audience: []string{audience},
		Subject:  subject,
	})
	token.Header["kid"] = kidHeader
	return token.SignedString(server.privateKey)
}
