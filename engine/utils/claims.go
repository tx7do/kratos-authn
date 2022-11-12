package utils

import (
	"bytes"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/tx7do/kratos-authn/engine"
)

func AuthClaimsToJwtClaims(raw engine.AuthClaims) jwt.Claims {
	claims := jwt.MapClaims{
		"sub": raw.Subject,
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

func MapClaimsToAuthClaims(rawClaims jwt.MapClaims) (*engine.AuthClaims, error) {
	// optional subject
	var subject = ""
	if subjectClaim, ok := rawClaims["sub"]; ok {
		if subject, ok = subjectClaim.(string); !ok {
			return nil, engine.ErrInvalidSubject
		}
	}

	claims := &engine.AuthClaims{
		Subject: subject,
		Scopes:  make(engine.ScopeSet),
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

func JwtClaimsToAuthClaims(rawClaims jwt.Claims) (*engine.AuthClaims, error) {
	claims, ok := rawClaims.(jwt.MapClaims)
	if !ok {
		return nil, engine.ErrInvalidClaims
	}
	return MapClaimsToAuthClaims(claims)
}
