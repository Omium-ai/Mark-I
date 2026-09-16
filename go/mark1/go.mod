module github.com/Omium-ai/omium-mark1/go/mark1

go 1.25.14

require (
	github.com/Omium-ai/omium-mark1/go/mark1d v0.0.0 // adapters/ ONLY: the 08 §8 fence engine. enable applies it, doctor classifies it, off reverts it — all three with the daemon down, so the algorithm cannot live behind the socket. Importing it beats a second copy: a revert implemented twice silently under-reverts, and each copy's own byte-equality test keeps passing while the two disagree about what a fence is.
	github.com/Omium-ai/omium-mark1/proto/gen/go v0.0.0 // indirect
	github.com/digitorus/pkcs7 v0.0.0-20230713084857-e76b763bdc49 // verify-release: the CMS signature inside an RFC 3161 timestamp (MIT); what sigstore-go itself uses, without its OTel/gRPC closure (CON-005)
	github.com/digitorus/timestamp v0.0.0-20231217203849-220c5c2851b7 // verify-release: RFC 3161 TimeStampResp parsing (BSD-2); its only dep is pkcs7
	github.com/spf13/cobra v1.9.1 // 7 subcommands with flags/help; the one boring choice
	google.golang.org/protobuf v1.36.11 // indirect
)

require (
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	golang.org/x/sys v0.42.0 // indirect
	lukechampine.com/blake3 v1.4.1 // indirect
)

replace github.com/Omium-ai/omium-mark1/proto/gen/go => ../../proto/gen/go

replace github.com/Omium-ai/omium-mark1/go/mark1d => ../mark1d
