module github.com/Omium-ai/omium-mark1/go/controld

go 1.25.0

require (
	github.com/Omium-ai/omium-mark1/proto/gen/go v0.0.0
	github.com/ClickHouse/clickhouse-go/v2 v2.34.0 // imported ONLY under internal/querychoke + internal/ingest/chproj — depguard-enforced (§7.3)
	github.com/aws/aws-sdk-go-v2 v1.36.0
	github.com/aws/aws-sdk-go-v2/config v1.29.0 // IRSA credential chain
	github.com/aws/aws-sdk-go-v2/service/kms v1.38.0 // section-split bundle signing, server chain key (05 §4.5)
	github.com/aws/aws-sdk-go-v2/service/s3 v1.79.0 // S3-first landing (05 §2)
	github.com/coreos/go-oidc/v3 v3.12.0 // tenant-IdP token verification (enroll)
	github.com/fxamacker/cbor/v2 v2.7.0 // canonical-CBOR bundle assembly (policydist)
	github.com/google/differential-privacy/go/v3 v3.0.0 // integer mechanisms ONLY (05 §5.2)
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.7.5 // pgxpool + tenant-GUC AfterConnect (05 §7.2)
	github.com/klauspost/compress v1.18.0 // zstd ingest decompression
	github.com/prometheus/client_golang v1.19.0 // estate pin; pod-annotation scraping
	golang.org/x/oauth2 v0.25.0
	google.golang.org/protobuf v1.36.11
)

replace github.com/Omium-ai/omium-mark1/proto/gen/go => ../../proto/gen/go
