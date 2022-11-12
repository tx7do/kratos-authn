package utils

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-kratos/kratos/v2/transport"

	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func extractTokenFromGrpcContext(ctx context.Context) string {
	return metautils.ExtractIncoming(ctx).Get(HeaderAuthorize)
}

func extractTokenFromKratosContext(ctx context.Context) string {
	if header, ok := transport.FromServerContext(ctx); ok {
		return header.RequestHeader().Get(HeaderAuthorize)
	}
	return ""
}

func extractTokenFromContext(ctx context.Context, useGrpc bool) string {
	if useGrpc {
		return extractTokenFromGrpcContext(ctx)
	} else {
		return extractTokenFromKratosContext(ctx)
	}
}

func AuthFromMD(ctx context.Context, expectedScheme string, useGrpc bool) (string, error) {
	val := extractTokenFromContext(ctx, useGrpc)
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

func MDWithAuth(ctx context.Context, expectedScheme string, tokenStr string, useGrpc bool) context.Context {
	if useGrpc {
		return injectTokenToGrpcContext(ctx, expectedScheme, tokenStr)
	} else {
		return injectTokenToKratosContext(ctx, expectedScheme, tokenStr)
	}
}
