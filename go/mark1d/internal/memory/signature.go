// Package memory is the edge half of REMEMBER delivery (06 §9.5, D-AE): the fail-static artifact cache, the per-task injection decision, and the LCB-fuel events.
package memory

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

const (
	signatureLines    = 2
	signatureMaxChars = 240
)

var (
	reLine  = regexp.MustCompile("\r\n|\r|\n")
	rePath  = regexp.MustCompile(`(?:[A-Za-z]:)?(?:[\\/][A-Za-z0-9_.\-]+){2,}`)
	reToken = regexp.MustCompile(`[a-z0-9]+`)
	reNum   = regexp.MustCompile(`[0-9]+`)
	reWS    = regexp.MustCompile(`[ \t\r\n]+`)
)

// NormalizeSignature is the byte-identical twin of retrieve.normalize_signature (python/intel/app/memory/retrieve.py).
func NormalizeSignature(text string) string {
	var lines []string
	for _, ln := range reLine.Split(text, -1) {
		if ln = strings.Trim(ln, " \t\r\n\f\v"); ln != "" {
			lines = append(lines, ln)
		}
		if len(lines) == signatureLines {
			break
		}
	}
	s := []rune(strings.Join(lines, " "))
	if len(s) > signatureMaxChars {
		s = s[:signatureMaxChars]
	}
	out := strings.ToLower(string(s))
	out = rePath.ReplaceAllString(out, "<path>")
	out = reToken.ReplaceAllStringFunc(out, hexToken)
	out = reNum.ReplaceAllString(out, "0")
	return strings.Trim(reWS.ReplaceAllString(out, " "), " \t\r\n\f\v")
}

func hexToken(t string) string {
	if len(t) < 6 {
		return t
	}
	digit := false
	for _, c := range t {
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'f':
		default:
			return t
		}
	}
	if !digit {
		return t
	}
	return "<hex>"
}

func SignatureDigest(normalized string) string {
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}
