// Package fence is the one drift classifier every strict-JSON fence shares
// (08 §8.4 as amended by ADR-0014): given the pre-image, the post-apply image
// and the file as it is now, say what moved — nothing, something outside our
// entries, something inside them, or our entries altogether. Pure: no I/O,
// no adapter knowledge beyond the fence convention itself (08 §8.1): an
// array element carrying `"_mark1"` is ours, a `_mark1_managed` object is
// ours, and nothing else is.
//
// "Outside the fence" for a strict-JSON file is the document with our keys
// removed, compared STRUCTURALLY (08 §8.1 fixes no byte layout for JSON a
// user may reformat), so a reindent, a CRLF rewrite or a trailing newline
// is DriftNone — the user changed no content of theirs — and a key they
// added anywhere is DriftOutsideFence.
package fence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// Drift is the four-way verdict. The names are 08 §8.4's.
type Drift int

const (
	DriftNone         Drift = iota // the file is exactly as we left it, structurally
	DriftOutsideFence              // our entries are intact; the user changed something else
	DriftInsideFence               // our entries are present but not what we wrote (08 §7.4 FRAGMENT-DAMAGED)
	FenceMissing                   // none of our entries is present (08 §7.4 MISSING)
)

func (d Drift) String() string {
	switch d {
	case DriftNone:
		return "none"
	case DriftOutsideFence:
		return "outside-fence"
	case DriftInsideFence:
		return "inside-fence"
	case FenceMissing:
		return "fence-missing"
	}
	return fmt.Sprintf("drift(%d)", int(d))
}

// entryTag and managedKey are 08 §8.1's fence convention for strict JSON.
const (
	entryTag   = "_mark1"
	managedKey = "_mark1_managed"
)

// Classify compares cur against post (and pre, which only informs the error
// text for a missing fence). Byte-identical ⇒ DriftNone without parsing.
// An unparseable cur is reported as FenceMissing with the parse error: a file
// we cannot read is one whose fence we cannot find, and the caller's existing
// handling for that case decides what to do.
func Classify(pre, post, cur []byte) (Drift, error) {
	if bytes.Equal(cur, post) {
		return DriftNone, nil
	}
	curDoc, err := decode(cur)
	if err != nil {
		return FenceMissing, fmt.Errorf("fence: current file is not strict JSON: %w", err)
	}
	postDoc, err := decode(post)
	if err != nil {
		return FenceMissing, fmt.Errorf("fence: post-apply image is not strict JSON: %w", err)
	}
	curOut, curIn := Split(curDoc)
	postOut, postIn := Split(postDoc)
	if len(postIn) == 0 || len(curIn) == 0 {
		// Nothing of ours in the file now, or nothing was ever fenced into it
		// (mechanism A, a no-op apply): there is no fence to classify against.
		return FenceMissing, nil
	}
	if !reflect.DeepEqual(curIn, postIn) {
		return DriftInsideFence, nil
	}
	if !reflect.DeepEqual(curOut, postOut) {
		return DriftOutsideFence, nil
	}
	return DriftNone, nil
}

// Split separates a decoded document into the part that is not ours (with
// every one of our entries removed, in place of nothing — an array an entry
// of ours was removed from keeps its other elements) and the list of our
// entries in document order. Ours: an object array element with the entryTag
// key, and the managedKey object wherever it sits.
func Split(doc any) (outside any, ours []any) {
	switch v := doc.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		// Keys in sorted order so ours is deterministic: a map ranges randomly,
		// and DeepEqual over two differently ordered lists is a coin toss.
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := v[k]
			if k == managedKey {
				ours = append(ours, map[string]any{managedKey: child})
				continue
			}
			o, in := Split(child)
			ours = append(ours, in...)
			out[k] = o
		}
		return out, ours
	case []any:
		out := make([]any, 0, len(v))
		for _, child := range v {
			if m, ok := child.(map[string]any); ok {
				if _, tagged := m[entryTag]; tagged {
					ours = append(ours, child)
					continue
				}
			}
			o, in := Split(child)
			ours = append(ours, in...)
			out = append(out, o)
		}
		return out, ours
	default:
		return v, nil
	}
}

func decode(b []byte) (any, error) {
	var doc any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}
