module github.com/eduardonunesp/bls-server/server

go 1.21.1

replace github.com/eduardonunesp/bls-server/commons => ../commons

require github.com/eduardonunesp/bls-server/commons v0.0.0-00010101000000-000000000000

require (
	github.com/chuwt/chia-bls-go v0.1.0 // indirect
	github.com/kilic/bls12-381 v0.1.0 // indirect
	golang.org/x/crypto v0.11.0 // indirect
	golang.org/x/sys v0.10.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)
