module github.com/Omium-ai/omium-mark1/go/mark1d

go 1.25.0

require (
	github.com/Omium-ai/omium-mark1/proto/gen/go v0.0.0
	github.com/edsrzf/mmap-go v1.2.0 // spool ledger mmap (07 §6)
	github.com/fsnotify/fsnotify v1.9.0 // transcript discovery watchers (04 §2.1)
	github.com/fxamacker/cbor/v2 v2.7.0 // Go parallel PolicyBundle decoder (04 §2.6)
	github.com/google/uuid v1.6.0 // UUIDv7 (RFC 9562)
	github.com/klauspost/compress v1.18.0 // zstd batch compression (04 §2.5)
	github.com/zalando/go-keyring v0.2.6 // key custody ladder, cgo-free (04 §2.9 — the cgo tax stays dead)
	golang.org/x/sys v0.42.0 // unix/windows syscall surface (fabric perms, statfs, job objects)
	google.golang.org/protobuf v1.36.11
)

replace github.com/Omium-ai/omium-mark1/proto/gen/go => ../../proto/gen/go
