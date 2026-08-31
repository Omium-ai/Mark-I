// Canonical CBOR (RFC 8949 §4.2.1) for PolicyBundle v1 — the Go twin of
// rust/mark1-policy/src/canon.rs. HAND-ROLLED, not a library: a lenient CBOR
// parser is precisely how a second byte representation of validly signed
// content gets accepted, making section signatures encoder-dependent (07
// §"PolicyBundle v1"). Where Rust decodes leniently and proves canonicality by
// re-encode-and-compare, this decoder REJECTS every non-canonical form at the
// byte it appears (definite lengths, minimal heads, strictly sorted map keys,
// shortest lossless float widths, NaN = f97e00) — same accepted set, same
// non_canonical rejection class. The encoder exists for the D-Q signing input
// and the body re-encode; decode(raw)→encode == raw by construction.

package policy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"unicode/utf8"
)

// maxDepth bounds nesting on both the decode and encode walks — hostile deep
// nesting must die in the reader, not in this process's stack (canon.rs
// MAX_DEPTH, kept identical).
const maxDepth = 32

// The decoded value model, mirroring ciborium's Value variants the schema
// uses: uint64 (major 0), nint (major 1), []byte, string, []any, vmap, vtag,
// bool, null, float64.
type (
	pair struct{ k, v any }
	// vmap keeps entries in wire order; the encoder re-sorts by encoded key.
	vmap []pair
	vtag struct {
		num   uint64
		inner any
	}
	// nint is a CBOR major-1 negative integer: value = -1 - int64(n).
	nint uint64
	// null is CBOR null as a distinct type, so "present as null" and
	// "absent" stay distinguishable in a map[string]any lookup.
	null struct{}
)

type cborReader struct {
	buf []byte
	pos int
}

// decodeCanonical parses exactly one canonical data item covering the whole
// buffer. Every error — malformed, truncated, trailing bytes, or any of the
// six non-canonical defect classes — is the M1E-3001 non_canonical rejection.
func decodeCanonical(raw []byte) (any, error) {
	r := &cborReader{buf: raw}
	v, err := r.item(0)
	if err != nil {
		return nil, err
	}
	if r.pos != len(raw) {
		return nil, fmt.Errorf("%d trailing byte(s) after the bundle", len(raw)-r.pos)
	}
	return v, nil
}

// take is the only writer of r.pos, and it advances only past the bound below, so
// 0 <= pos <= len(buf) holds for the reader's whole life and len(buf)-pos is never
// negative. The comparison stays in uint64 deliberately: a hostile 8-byte head
// carries n up to 2^64-1, which must not wrap on its way down to int.
func (r *cborReader) take(n uint64) ([]byte, error) {
	if n > uint64(len(r.buf)-r.pos) { //nolint:gosec // G115: pos <= len(buf) — see above
		return nil, errors.New("truncated data item")
	}
	b := r.buf[r.pos : r.pos+int(n)] //nolint:gosec // G115: n <= len(buf)-pos, just checked
	r.pos += int(n)                  //nolint:gosec // G115: same bound
	return b, nil
}

func minimalArg(ai byte, arg uint64) bool {
	switch ai {
	case 24:
		return arg >= 24
	case 25:
		return arg >= 0x100
	case 26:
		return arg >= 0x1_0000
	default: // 27
		return arg >= 0x1_0000_0000
	}
}

// head reads one data-item head, enforcing minimal-length argument encoding.
// Major 7's ai 25..27 select float widths, not magnitudes — width canonicality
// is the caller's value-level check, so minimality is skipped there.
func (r *cborReader) head() (major, ai byte, arg uint64, err error) {
	b, err := r.take(1)
	if err != nil {
		return 0, 0, 0, err
	}
	major, ai = b[0]>>5, b[0]&0x1f
	switch {
	case ai < 24:
		arg = uint64(ai)
	case ai <= 27:
		raw, e := r.take(uint64(1) << (ai - 24))
		if e != nil {
			return 0, 0, 0, e
		}
		for _, c := range raw {
			arg = arg<<8 | uint64(c)
		}
		if major != 7 && !minimalArg(ai, arg) {
			return 0, 0, 0, fmt.Errorf("non-minimal head: %d encoded with ai %d", arg, ai)
		}
	case ai == 31:
		return 0, 0, 0, errors.New("indefinite length is non-canonical")
	default:
		return 0, 0, 0, fmt.Errorf("reserved additional info %d", ai)
	}
	return major, ai, arg, nil
}

func (r *cborReader) item(depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("nesting exceeds maxDepth")
	}
	major, ai, arg, err := r.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		return arg, nil
	case 1:
		return nint(arg), nil
	case 2:
		b, err := r.take(arg)
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), b...), nil
	case 3:
		b, err := r.take(arg)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(b) {
			return nil, errors.New("text is not valid UTF-8")
		}
		return string(b), nil
	case 4:
		var items []any
		for i := uint64(0); i < arg; i++ {
			it, err := r.item(depth + 1)
			if err != nil {
				return nil, err
			}
			items = append(items, it)
		}
		return items, nil
	case 5:
		var entries vmap
		var prevKey []byte
		for i := uint64(0); i < arg; i++ {
			start := r.pos
			k, err := r.item(depth + 1)
			if err != nil {
				return nil, err
			}
			kb := r.buf[start:r.pos]
			// §4.2.1 key order is strict: an out-of-order key and a
			// duplicate key are both inexpressible in canonical form.
			if prevKey != nil && bytes.Compare(prevKey, kb) >= 0 {
				return nil, errors.New("map keys not in strict canonical order")
			}
			prevKey = kb
			v, err := r.item(depth + 1)
			if err != nil {
				return nil, err
			}
			entries = append(entries, pair{k, v})
		}
		return entries, nil
	case 6:
		// RFC 8949 §4.2.2: tags 2/3 (bignum) are a non-preferred encoding of a
		// value the basic majors already express — the same defect class as
		// `non_canonical_nonminimal_int`, so it dies HERE, not later as a type
		// mismatch. ciborium normalizes 2/3 to an integer and the Rust twin
		// fails its re-encode compare; a vtag round-trips verbatim, so without
		// this guard the two decoders classify one buffer two ways.
		if arg == 2 || arg == 3 {
			return nil, errors.New("bignum tag is not a preferred integer encoding")
		}
		inner, err := r.item(depth + 1)
		if err != nil {
			return nil, err
		}
		return vtag{arg, inner}, nil
	default: // 7
		switch ai {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return null{}, nil
		case 25:
			h := uint16(arg) //nolint:gosec // G115: ai 25 ⇒ head() read exactly 2 bytes ⇒ arg <= 0xffff
			f := f16ToF64(h)
			if math.IsNaN(f) && h != 0x7e00 {
				return nil, errors.New("NaN must canonicalize to f97e00")
			}
			return f, nil
		case 26:
			f32 := math.Float32frombits(uint32(arg)) //nolint:gosec // G115: ai 26 ⇒ 4 bytes ⇒ arg <= 0xffffffff
			if math.IsNaN(float64(f32)) {
				return nil, errors.New("NaN must canonicalize to f97e00")
			}
			if _, ok := f32ToF16Lossless(f32); ok {
				return nil, errors.New("float widened beyond shortest lossless form")
			}
			return float64(f32), nil
		case 27:
			f := math.Float64frombits(arg)
			if math.IsNaN(f) {
				return nil, errors.New("NaN must canonicalize to f97e00")
			}
			if float64(float32(f)) == f {
				return nil, errors.New("float widened beyond shortest lossless form")
			}
			return f, nil
		default:
			// Simple values (incl. undefined, ai 24's extended form and the
			// stray break) have no canonical meaning in this schema.
			return nil, fmt.Errorf("major 7 additional info %d has no canonical encoding here", ai)
		}
	}
}

// encodeCanonical is the deterministic encoding of v per RFC 8949 §4.2.1 —
// canon.rs encode_canonical, used for the D-Q signing input, the section
// bytes and the body re-encode.
func encodeCanonical(v any) ([]byte, error) {
	return appendValue(nil, v, 0)
}

func appendHead(out []byte, major byte, arg uint64) []byte {
	m := major << 5
	switch {
	case arg < 24:
		return append(out, m|byte(arg))
	case arg <= 0xff:
		return append(out, m|24, byte(arg))
	case arg <= 0xffff:
		return append(out, m|25, byte(arg>>8), byte(arg))
	case arg <= 0xffff_ffff:
		return binary.BigEndian.AppendUint32(append(out, m|26), uint32(arg))
	default:
		return binary.BigEndian.AppendUint64(append(out, m|27), arg)
	}
}

func appendValue(out []byte, v any, depth int) ([]byte, error) {
	if depth > maxDepth {
		return nil, errors.New("nesting exceeds maxDepth")
	}
	switch t := v.(type) {
	case uint64:
		return appendHead(out, 0, t), nil
	case nint:
		return appendHead(out, 1, uint64(t)), nil
	case []byte:
		return append(appendHead(out, 2, uint64(len(t))), t...), nil
	case string:
		return append(appendHead(out, 3, uint64(len(t))), t...), nil
	case []any:
		out = appendHead(out, 4, uint64(len(t)))
		for _, item := range t {
			var err error
			if out, err = appendValue(out, item, depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	case vmap:
		// Sort by encoded-key bytes (§4.2.1); adjacent equals after the
		// sort are the duplicate-key rejection.
		type encEntry struct {
			kb []byte
			v  any
		}
		enc := make([]encEntry, 0, len(t))
		for _, e := range t {
			kb, err := appendValue(nil, e.k, depth+1)
			if err != nil {
				return nil, err
			}
			enc = append(enc, encEntry{kb, e.v})
		}
		sort.Slice(enc, func(i, j int) bool { return bytes.Compare(enc[i].kb, enc[j].kb) < 0 })
		for i := 1; i < len(enc); i++ {
			if bytes.Equal(enc[i-1].kb, enc[i].kb) {
				return nil, errors.New("duplicate map key")
			}
		}
		out = appendHead(out, 5, uint64(len(enc)))
		for _, e := range enc {
			out = append(out, e.kb...)
			var err error
			if out, err = appendValue(out, e.v, depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	case vtag:
		return appendValue(appendHead(out, 6, t.num), t.inner, depth+1)
	case bool:
		if t {
			return append(out, 0xf5), nil
		}
		return append(out, 0xf4), nil
	case null:
		return append(out, 0xf6), nil
	case float64:
		return appendFloat(out, t), nil
	default:
		return nil, fmt.Errorf("value of type %T has no canonical encoding", v)
	}
}

// appendFloat is preferred serialization (§4.2.1): the shortest float width
// preserving the value exactly; NaN canonicalizes to the half-width quiet NaN
// 0xf97e00 (payloads dropped — two NaNs must not be two encodings).
func appendFloat(out []byte, f float64) []byte {
	if math.IsNaN(f) {
		return append(out, 0xf9, 0x7e, 0x00)
	}
	f32 := float32(f)
	if float64(f32) == f {
		if h, ok := f32ToF16Lossless(f32); ok {
			return append(out, 0xf9, byte(h>>8), byte(h))
		}
		return binary.BigEndian.AppendUint32(append(out, 0xfa), math.Float32bits(f32))
	}
	return binary.BigEndian.AppendUint64(append(out, 0xfb), math.Float64bits(f))
}

// f32ToF16Lossless converts to binary16 bits only when exact (the "preserves
// the value" precondition for the 2-byte form). NaN never reaches here.
func f32ToF16Lossless(x float32) (uint16, bool) {
	bits := math.Float32bits(x)
	sign := uint16(bits>>16) & 0x8000 //nolint:gosec // G115: bits is uint32, so bits>>16 <= 0xffff
	exp := int(bits>>23) & 0xff
	man := bits & 0x007f_ffff
	if exp == 0 {
		// f32 zero is f16 zero; f32 subnormals are far below f16's
		// subnormal floor and can never be exact.
		if man == 0 {
			return sign, true
		}
		return 0, false
	}
	if exp == 0xff {
		// ±infinity (the caller handled NaN).
		if man == 0 {
			return sign | 0x7c00, true
		}
		return 0, false
	}
	e := exp - 127
	if e >= -14 && e <= 15 {
		// Normal f16: the 23-bit mantissa must fit in 10 bits.
		if man&0x1fff != 0 {
			return 0, false
		}
		//nolint:gosec // G115: the enclosing guard pins e to [-14,15] so e+15 is [1,30]; man is 23-bit so man>>13 <= 0x3ff
		return sign | uint16(e+15)<<10 | uint16(man>>13), true
	}
	if e >= -24 && e <= -15 {
		// Subnormal f16: the f32 significand (implicit leading 1) shifted
		// down; every dropped bit must be zero.
		full := uint32(0x0080_0000) | man
		sh := uint(-(e + 1)) //nolint:gosec // G115: enclosing guard pins e to [-24,-15] ⇒ 14..=23
		if full&(1<<sh-1) == 0 {
			m16 := full >> sh
			if m16 >= 1 && m16 <= 0x3ff {
				return sign | uint16(m16), true
			}
		}
	}
	return 0, false
}

func f16ToF64(h uint16) float64 {
	exp := int(h>>10) & 0x1f
	man := h & 0x3ff
	var f float64
	switch exp {
	case 0:
		f = float64(man) * 0x1p-24
	case 31:
		if man != 0 {
			return math.NaN()
		}
		f = math.Inf(1)
	default:
		f = math.Ldexp(float64(1024+man), exp-25)
	}
	if h&0x8000 != 0 {
		f = -f
	}
	return f
}
