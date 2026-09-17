module github.com/Omium-ai/omium-mark1/go/controld

go 1.25.14

require (
	github.com/ClickHouse/clickhouse-go/v2 v2.34.0 // imported ONLY under internal/querychoke + internal/ingest/chproj — depguard-enforced (§7.3)
	github.com/Omium-ai/omium-mark1/proto/gen/go v0.0.0
	github.com/aws/aws-sdk-go-v2 v1.41.5
	github.com/aws/aws-sdk-go-v2/config v1.29.0 // IRSA credential chain
	github.com/aws/aws-sdk-go-v2/service/s3 v1.97.3 // S3-first landing (05 §2)
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.9.2 // pgxpool + tenant-GUC AfterConnect (05 §7.2)
	github.com/klauspost/compress v1.18.0 // zstd ingest decompression
	github.com/prometheus/client_golang v1.19.0 // estate pin; pod-annotation scraping
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/ClickHouse/ch-go v0.65.1 // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.8 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.53 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.24 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.22 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.8 // indirect
	github.com/aws/smithy-go v1.24.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/coreos/go-oidc/v3 v3.12.0 // tenant-IdP token verification (enroll, 13 §3.4 pin)
	github.com/fxamacker/cbor/v2 v2.7.0
	github.com/go-faster/city v1.0.1 // indirect
	github.com/go-faster/errors v0.7.1 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // pinned-JWKS parsing (05 §10.1 B2); already go-oidc's own jose
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/paulmach/orb v0.11.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.48.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	go.opentelemetry.io/otel v1.35.0 // indirect
	go.opentelemetry.io/otel/trace v1.35.0 // indirect
	golang.org/x/oauth2 v0.27.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/text v0.39.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/google/differential-privacy/go/v4 v4.1.0 // dprelease integer mechanisms only (05 §5.2)
	lukechampine.com/blake3 v1.4.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/glog v1.2.5 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	gonum.org/v1/gonum v0.16.0 // indirect
)

replace github.com/Omium-ai/omium-mark1/proto/gen/go => ../../proto/gen/go
