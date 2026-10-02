module github.com/Omium-ai/omium-mark1/conformance/emitter

go 1.25.14

// The reference external writer (08 §4.6): generated m1p.v1 bindings and nothing else,
// so a partner can reproduce it from the contract alone.
require (
	github.com/Omium-ai/omium-mark1/proto/gen/go v0.0.0
	google.golang.org/protobuf v1.36.11
)

replace github.com/Omium-ai/omium-mark1/proto/gen/go => ../../proto/gen/go
