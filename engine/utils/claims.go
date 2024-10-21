package utils

import (
	"bytes"
	"strings"

	jwtV5 "github.com/golang-jwt/jwt/v5"

	"github.com/tx7do/kratos-authn/engine"
)

func AuthClaimsToJwtClaims(raw engine.AuthClaims) jwtV5.Claims {
	claims := jwtV5.MapClaims{
		"sub": raw.Subject,
	}

	if raw.Issuer != "" {
		claims["iss"] = raw.Issuer
	}
	if raw.Audience != "" {
		claims["aud"] = raw.Audience
	}
	if raw.Expiration != "" {
		claims["exp"] = raw.Expiration
	}

	var buffer bytes.Buffer
	count := len(raw.Scopes)
	idx := 0
	for scope := range raw.Scopes {
		buffer.WriteString(scope)
		if idx != count-1 {
			buffer.WriteString(" ")
		}
		idx++
	}
	str := buffer.String()
	if len(str) > 0 {
		claims["scope"] = buffer.String()
	}

	return claims
}

func MapClaimsToAuthClaims(rawClaims jwtV5.MapClaims) (*engine.AuthClaims, error) {
	claims := &engine.AuthClaims{
		Scopes: make(engine.ScopeSet),
	}

	// optional Subject
	if subjectClaim, ok := rawClaims["sub"]; ok {
		if claims.Subject, ok = subjectClaim.(string); !ok {
			return nil, engine.ErrInvalidSubject
		}
	}
	// optional Issuer
	if issuerClaim, ok := rawClaims["iss"]; ok {
		if claims.Issuer, ok = issuerClaim.(string); !ok {
			return nil, engine.ErrInvalidIssuer
		}
	}
	// optional Audience
	if audienceClaim, ok := rawClaims["aud"]; ok {
		if claims.Audience, ok = audienceClaim.(string); !ok {
			return nil, engine.ErrInvalidAudience
		}
	}
	// optional Expiration
	if expirationClaim, ok := rawClaims["exp"]; ok {
		if claims.Expiration, ok = expirationClaim.(string); !ok {
			return nil, engine.ErrInvalidExpiration
		}
	}

	// optional scopes
	if scopeKey, ok := rawClaims["scope"]; ok {
		if scope, ok := scopeKey.(string); ok {
			scopes := strings.Split(scope, " ")
			for _, s := range scopes {
				claims.Scopes[s] = true
			}
		}
	}

	return claims, nil
}

func JwtClaimsToAuthClaims(rawClaims jwtV5.Claims) (*engine.AuthClaims, error) {
	claims, ok := rawClaims.(jwtV5.MapClaims)
	if !ok {
		return nil, engine.ErrInvalidClaims
	}
	return MapClaimsToAuthClaims(claims)
}
