module github.com/tx7do/kratos-authn/engine/oidc

go 1.19

require (
	github.com/MicahParks/keyfunc v1.8.0
	github.com/go-kratos/kratos/v2 v2.5.3
	github.com/golang-jwt/jwt/v4 v4.4.3
	github.com/hashicorp/go-retryablehttp v0.7.1
	github.com/stretchr/testify v1.8.1
	github.com/tx7do/kratos-authn v0.0.6
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-playground/form/v4 v4.2.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	google.golang.org/genproto v0.0.0-20221207170731-23e4bf6bdc37 // indirect
	google.golang.org/grpc v1.51.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/tx7do/kratos-authn => ../../
