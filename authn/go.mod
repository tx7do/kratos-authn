module github.com/tx7do/kratos-authn/authn

go 1.19

replace github.com/tx7do/kratos-authn => ../

require (
	github.com/go-kratos/kratos/v2 v2.5.3
	github.com/golang-jwt/jwt/v4 v4.4.3
	github.com/stretchr/testify v1.8.1
	github.com/tx7do/kratos-authn v0.0.5
	github.com/tx7do/kratos-authn/engine/jwt v0.0.0-20221113094443-0674ebc7a3b3
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-playground/form/v4 v4.2.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	google.golang.org/genproto v0.0.0-20221118155620-16455021b5e6 // indirect
	google.golang.org/grpc v1.51.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
