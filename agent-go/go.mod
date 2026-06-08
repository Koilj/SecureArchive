module securedata-agent

// NOTE: Go 1.24 is not widely available. Use a stable toolchain.
// If your system uses a different Go version, set this accordingly.
go 1.24.0

toolchain go1.24.11

require (
	github.com/hyperledger/fabric-gateway v1.10.0
	google.golang.org/grpc v1.78.0
)

require (
	github.com/hyperledger/fabric-protos-go-apiv2 v0.3.7 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251029180050-ab9386a59fda // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)
