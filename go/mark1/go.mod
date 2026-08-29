module github.com/Omium-ai/omium-mark1/go/mark1

go 1.25.0

require (
	github.com/Omium-ai/omium-mark1/proto/gen/go v0.0.0
	github.com/spf13/cobra v1.9.1 // 7 subcommands with flags/help; the one boring choice
	github.com/zalando/go-keyring v0.2.6 // enroll writes the device key through the same custody ladder
	golang.org/x/oauth2 v0.25.0 // OIDC device-code flow client side (08 §3.1)
	google.golang.org/protobuf v1.36.11
)

replace github.com/Omium-ai/omium-mark1/proto/gen/go => ../../proto/gen/go
