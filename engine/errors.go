package engine

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthErrorCode int32

const (
	AuthErrorCodeAuthFailedInvalidSubject     AuthErrorCode = 1001
	AuthErrorCodeAuthFailedInvalidAudience    AuthErrorCode = 1002
	AuthErrorCodeAuthFailedInvalidIssuer      AuthErrorCode = 1003
	AuthErrorCodeInvalidClaims                AuthErrorCode = 1004
	AuthErrorCodeAuthFailedInvalidBearerToken AuthErrorCode = 1005

	AuthErrorCodeUnauthenticated          AuthErrorCode = 1500
	AuthErrorCodeBearerTokenMissing       AuthErrorCode = 1010
	AuthErrorCodeTokenExpired             AuthErrorCode = 1011
	AuthErrorCodeUnsupportedSigningMethod AuthErrorCode = 1012
	AuthErrorCodeMissingKeyFunc           AuthErrorCode = 1014
	AuthErrorCodeSignTokenFailed          AuthErrorCode = 1015
	AuthErrorCodeGetKeyFailed             AuthErrorCode = 1016

	AuthCodeNoAtHash      AuthErrorCode = 1050
	AuthCodeInvalidAtHash AuthErrorCode = 1051
)

var (
	ErrInvalidSubject  = status.Error(codes.Code(AuthErrorCodeAuthFailedInvalidSubject), "invalid subject")
	ErrInvalidAudience = status.Error(codes.Code(AuthErrorCodeAuthFailedInvalidAudience), "invalid audience")
	ErrInvalidIssuer   = status.Error(codes.Code(AuthErrorCodeAuthFailedInvalidIssuer), "invalid issuer")
	ErrInvalidClaims   = status.Error(codes.Code(AuthErrorCodeInvalidClaims), "invalid claims")
	ErrInvalidToken    = status.Error(codes.Code(AuthErrorCodeAuthFailedInvalidBearerToken), "invalid bearer token")

	ErrMissingBearerToken       = status.Error(codes.Code(AuthErrorCodeBearerTokenMissing), "missing bearer token")
	ErrUnauthenticated          = status.Error(codes.Code(AuthErrorCodeUnauthenticated), "unauthenticated")
	ErrTokenExpired             = status.Error(codes.Code(AuthErrorCodeTokenExpired), "token expired")
	ErrUnsupportedSigningMethod = status.Error(codes.Code(AuthErrorCodeUnsupportedSigningMethod), "unsupported signing method")
	ErrMissingKeyFunc           = status.Error(codes.Code(AuthErrorCodeMissingKeyFunc), "missing keyFunc")
	ErrSignTokenFailed          = status.Error(codes.Code(AuthErrorCodeSignTokenFailed), "sign token failed")
	ErrGetKeyFailed             = status.Error(codes.Code(AuthErrorCodeGetKeyFailed), "get key failed")

	ErrNoAtHash      = status.Error(codes.Code(AuthCodeNoAtHash), "id token did not have an access token hash")
	ErrInvalidAtHash = status.Error(codes.Code(AuthCodeInvalidAtHash), "access token hash does not match value in ID token")
)
