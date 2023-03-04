package utils

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-kratos/kratos/v2/transport"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"

	"github.com/tx7do/kratos-authn/engine"
)

// MDWithAuth .
func MDWithAuth(ctx context.Context, expectedScheme string, tokenStr string, ctxType engine.ContextType) context.Context {
	switch ctxType {
	case engine.ContextTypeGrpc:
		return injectTokenToGrpcContext(ctx, expectedScheme, tokenStr)
	case engine.ContextTypeKratosMetaData:
		return injectTokenToKratosContext(ctx, expectedScheme, tokenStr)
	default:
		return injectTokenToGrpcContext(ctx, expectedScheme, tokenStr)
	}
}

// AuthFromMD .
func AuthFromMD(ctx context.Context, expectedScheme string, ctxType engine.ContextType) (string, error) {
	val := extractTokenFromContext(ctx, ctxType)
	if val == "" {
		return "", status.Errorf(codes.Unauthenticated, "Request unauthenticated with "+expectedScheme)
	}

	splits := strings.SplitN(val, " ", 2)
	if len(splits) < 2 {
		return "", status.Errorf(codes.Unauthenticated, "Bad authorization string")
	}

	if !strings.EqualFold(splits[0], expectedScheme) {
		return "", status.Errorf(codes.Unauthenticated, "Request unauthenticated with "+expectedScheme)
	}

	return splits[1], nil
}

func extractTokenFromGrpcContext(ctx context.Context) string {
	return metautils.ExtractIncoming(ctx).Get(HeaderAuthorize)
}

func extractTokenFromKratosContext(ctx context.Context) string {
	if header, ok := transport.FromServerContext(ctx); ok {
		return header.RequestHeader().Get(HeaderAuthorize)
	}
	return ""
}

func extractTokenFromContext(ctx context.Context, ctxType engine.ContextType) string {
	switch ctxType {
	case engine.ContextTypeGrpc:
		return extractTokenFromGrpcContext(ctx)
	case engine.ContextTypeKratosMetaData:
		return extractTokenFromKratosContext(ctx)
	default:
		return extractTokenFromGrpcContext(ctx)
	}
}

func formatToken(expectedScheme string, tokenStr string) string {
	return fmt.Sprintf("%s %s", expectedScheme, tokenStr)
}

func injectTokenToKratosContext(ctx context.Context, expectedScheme string, tokenStr string) context.Context {
	if header, ok := transport.FromClientContext(ctx); ok {
		header.RequestHeader().Set(HeaderAuthorize, formatToken(expectedScheme, tokenStr))
	} else {
		//log.Error("authn token injection failure in kratos context")
	}
	return ctx
}

func injectTokenToGrpcContext(ctx context.Context, expectedScheme string, tokenStr string) context.Context {
	metautils.ExtractOutgoing(ctx).Set(HeaderAuthorize, formatToken(expectedScheme, tokenStr))
	return ctx
}
