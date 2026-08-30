// S3Publisher — the customer-object-lock destination (m1_003 destination 2;
// 05 §4.4: heads published to `witness/heads/…`). PutObject with an
// object-lock retain-until date: retention is what turns "we uploaded it"
// into "nobody, including the bucket owner, can remove it before this date".
// The transparency-log destination (m1_003 destination 1) belongs to
// policydist's tlog (05 §4.4) and plugs in as a second Publisher when WS-6
// lands it.

package receipts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
)

type S3PublisherOptions struct {
	Bucket string
	// Endpoint is set only for the dev/compose MinIO stack (13 §11 C4);
	// empty means the real AWS endpoint resolution chain.
	Endpoint string
	// Retain is the object-lock horizon. Zero disables the lock header —
	// dev MinIO buckets without object-lock refuse the header outright, and
	// a dev stack witness is exercise, not evidence.
	Retain time.Duration
	Now    func() time.Time
}

type S3Publisher struct {
	client *s3.Client
	opts   S3PublisherOptions
}

func NewS3Publisher(ctx context.Context, o S3PublisherOptions) (*S3Publisher, error) {
	if o.Bucket == "" {
		return nil, fmt.Errorf("receipts: witness bucket is required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	client := s3.NewFromConfig(awsCfg, func(s3o *s3.Options) {
		if o.Endpoint != "" {
			s3o.BaseEndpoint = aws.String(o.Endpoint)
			s3o.UsePathStyle = true
		}
	})
	return &S3Publisher{client: client, opts: o}, nil
}

// Publish writes one JSON document per head: the signed statement verbatim
// plus its signature and key id — everything the offline verifier needs to
// check the head with no Omium API in the loop (08 §3.5's posture).
func (p *S3Publisher) Publish(ctx context.Context, tenant uuid.UUID, statement, signature []byte, keyID string) (Destination, error) {
	now := p.opts.Now().UTC()
	// Key layout: witness/heads/<tenant>/<RFC3339>.json (05 §4.4's
	// `witness/heads/…` prefix); time-suffixed so hourly heads never
	// overwrite — overwriting a witness would BE the rewrite the control
	// detects.
	key := fmt.Sprintf("witness/heads/%s/%s.json", tenant, now.Format("2006-01-02T15-04-05Z"))
	doc, err := json.Marshal(map[string]string{
		"statement":     string(statement),
		"signature_hex": fmt.Sprintf("%x", signature),
		"server_key_id": keyID,
	})
	if err != nil {
		return Destination{}, err
	}
	in := &s3.PutObjectInput{
		Bucket:      aws.String(p.opts.Bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(doc),
		ContentType: aws.String("application/json"),
	}
	var retainUntil time.Time
	if p.opts.Retain > 0 {
		retainUntil = now.Add(p.opts.Retain)
		in.ObjectLockMode = s3types.ObjectLockModeCompliance
		in.ObjectLockRetainUntilDate = aws.Time(retainUntil)
	} else {
		// m1_003's object destination requires a retain horizon; without the
		// lock the honest value is "no retention", recorded as now — the row
		// still names WHERE the copy is, which is its support job.
		retainUntil = now
	}
	out, err := p.client.PutObject(ctx, in)
	if err != nil {
		return Destination{}, err
	}
	uri := fmt.Sprintf("s3://%s/%s", p.opts.Bucket, key)
	etag := aws.ToString(out.ETag)
	return Destination{BucketURI: &uri, ETag: &etag, RetainUntil: &retainUntil}, nil
}
