module github.com/Omium-ai/omium-mark1/go/mark1d

go 1.25.14

require (
	github.com/Microsoft/go-winio v0.6.2 // 07 §5 Windows named pipe: ListenPipe with an SDDL DACL (fabric)
	github.com/Omium-ai/omium-mark1/proto/gen/go v0.0.0
	github.com/fsnotify/fsnotify v1.9.0 // transcript discovery watchers (04 §2.1)
	github.com/google/uuid v1.6.0 // UUIDv7 (RFC 9562)
	github.com/klauspost/compress v1.18.0 // zstd batch compression (04 §2.5)
	golang.org/x/crypto v0.37.0 // spill-ring unseal: the X25519 + ChaCha20-Poly1305 twin of spill.rs (04 §5.4)
	golang.org/x/sys v0.42.0 // unix/windows syscall surface (fabric perms, statfs, job objects)
	google.golang.org/protobuf v1.36.11
	lukechampine.com/blake3 v1.4.1 // checkpoint Merkle (04 §7.2 names BLAKE3; stdlib has none — pure Go, cgo-free)
)

require github.com/klauspost/cpuid/v2 v2.0.9 // indirect

replace github.com/Omium-ai/omium-mark1/proto/gen/go => ../../proto/gen/go
