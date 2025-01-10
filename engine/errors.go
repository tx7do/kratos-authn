package engine

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthErrorCode int32

const (
	AuthErrorCodeInvalidType AuthErrorCode = 500

	AuthErrorCodeInvalidJwtID                 AuthErrorCode = 1001
	AuthErrorCodeMissingJwtId                 AuthErrorCode = 1002
	AuthErrorCodeInvalidClaims                AuthErrorCode = 1003
	AuthErrorCodeAuthFailedInvalidBearerToken AuthErrorCode = 1004
	AuthErrorCodeAuthFailedInvalidSubject     AuthErrorCode = 1005
	AuthErrorCodeAuthFailedInvalidAudience    AuthErrorCode = 1006
	AuthErrorCodeAuthFailedInvalidIssuer      AuthErrorCode = 1007
	AuthErrorCodeAuthFailedInvalidExpiration  AuthErrorCode = 1008
	AuthErrorCodeAuthFailedInvalidNotBefore   AuthErrorCode = 1009
	AuthErrorCodeAuthFailedInvalidIssuedAt    AuthErrorCode = 1010

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
	ErrorInvalidType = status.Error(codes.Code(AuthErrorCodeInvalidType), "invalid type")

	ErrInvalidJwtID      = status.Error(codes.Code(AuthErrorCodeInvalidJwtID), "invalid jwt id")
	ErrMissingJwtId      = status.Error(codes.Code(AuthErrorCodeMissingJwtId), "jwt id missing")
	ErrInvalidSubject    = status.Error(codes.Code(AuthErrorCodeAuthFailedInvalidSubject), "invalid subject")
	ErrInvalidAudience   = status.Error(codes.Code(AuthErrorCodeAuthFailedInvalidAudience), "invalid audience")
	ErrInvalidIssuer     = status.Error(codes.Code(AuthErrorCodeAuthFailedInvalidIssuer), "invalid issuer")
	ErrInvalidExpiration = status.Error(codes.Code(AuthErrorCodeAuthFailedInvalidExpiration), "invalid expiration")
	ErrInvalidNotBefore  = status.Error(codes.Code(AuthErrorCodeAuthFailedInvalidNotBefore), "invalid not before")
	ErrInvalidIssuedAt   = status.Error(codes.Code(AuthErrorCodeAuthFailedInvalidIssuedAt), "invalid issued at")
	ErrInvalidClaims     = status.Error(codes.Code(AuthErrorCodeInvalidClaims), "invalid claims")
	ErrInvalidToken      = status.Error(codes.Code(AuthErrorCodeAuthFailedInvalidBearerToken), "invalid bearer token")

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
