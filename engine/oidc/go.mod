module github.com/tx7do/kratos-authn/engine/oidc

go 1.19

require (
	github.com/MicahParks/keyfunc v1.9.0
	github.com/go-kratos/kratos/v2 v2.6.1
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/hashicorp/go-retryablehttp v0.7.2
	github.com/stretchr/testify v1.8.2
	github.com/tx7do/kratos-authn v0.0.8
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-playground/form/v4 v4.2.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	google.golang.org/genproto v0.0.0-20230306155012-7f2fa6fef1f4 // indirect
	google.golang.org/grpc v1.53.0 // indirect
	google.golang.org/protobuf v1.29.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/tx7do/kratos-authn => ../../
