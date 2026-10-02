package cursor

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"

	"github.com/klauspost/compress/zstd"
)

// The manifest's post_image (08 §8.2, ADR-0014): the bytes we wrote, stored
// the way pre_image is, so revert can classify drift structurally instead of
// by whole-file hash. Additive: a manifest without it reverts as before.

// encodeImage is pre_image/post_image's encoding: zstd, then base64.
func encodeImage(b []byte) (string, error) {
	z, err := zstdCompress(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(z), nil
}

// RestorePostImage returns the bytes we wrote at apply, verified against
// post_image_hash; os.ErrNotExist-like absence is ErrNoPostImage, which a
// caller treats as "classify the old way".
func RestorePostImage(m Manifest) ([]byte, error) {
	if m.PostImage == "" {
		return nil, ErrNoPostImage
	}
	z, err := base64.StdEncoding.DecodeString(m.PostImage)
	if err != nil {
		return nil, err
	}
	r, err := zstd.NewReader(bytes.NewReader(z))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if sum(out) != m.PostImageHash {
		return nil, errors.New("post_image does not match post_image_hash")
	}
	return out, nil
}

// ErrNoPostImage: the manifest predates ADR-0014.
var ErrNoPostImage = errors.New("manifest carries no post_image")
