module github.com/tx7do/kratos-authn/middleware

go 1.25.0

replace (
	github.com/tx7do/kratos-authn => ../
	github.com/tx7do/kratos-authn/engine/jwt => ../engine/jwt
)

require (
	github.com/go-kratos/kratos/v2 v2.9.2
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/stretchr/testify v1.11.1
	github.com/tx7do/kratos-authn v1.1.10
	github.com/tx7do/kratos-authn/engine/jwt v1.1.10
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-playground/form/v4 v4.3.0 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260420184626-e10c466a9529 // indirect
	google.golang.org/grpc v1.80.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
