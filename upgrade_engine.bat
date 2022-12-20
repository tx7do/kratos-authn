cd .\engine\jwt\
go get all
go mod tidy

cd ..\..\engine\oidc\
go get all
go mod tidy

cd ..\..\engine\presharedkey\
go get all
go mod tidy

pause