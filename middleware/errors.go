package middleware

import "github.com/go-kratos/kratos/v2/errors"

const (
	reason string = "UNAUTHORIZED"
)

var (
	ErrUnauthorized = errors.Unauthorized(reason, "unauthorized access")
)
