package fence

import (
	"strings"
	"testing"
)

// A settings.json before Mark 1, after our apply (one tagged Stop hook, the
// managed object) and the variations a second writer or the user produce.
const (
	pre  = "{\n  \"theme\": \"dark\",\n  \"hooks\": {\n    \"Stop\": [\n      {\"matcher\": \"\", \"hooks\": [{\"type\": \"command\", \"command\": \"theirs\"}]}\n    ]\n  }\n}\n"
	post = "{\n  \"theme\": \"dark\",\n  \"hooks\": {\n    \"Stop\": [\n      {\"matcher\": \"\", \"hooks\": [{\"type\": \"command\", \"command\": \"theirs\"}]},\n      {\"matcher\": \"\", \"hooks\": [{\"type\": \"command\", \"command\": \"mark1-hookshim\"}], \"_mark1\": \"v1\"}\n    ]\n  },\n  \"_mark1_managed\": {\"version\": 1, \"pointers\": [\"/hooks/Stop/1\"]}\n}\n"
)

func TestClassifyTable(t *testing.T) {
	for _, tc := range []struct {
		name string
		cur  string
		want Drift
	}{
		{"byte-identical", post, DriftNone},
		{"CRLF rewrite", strings.ReplaceAll(post, "\n", "\r\n"), DriftNone},
		{"trailing newline dropped", strings.TrimRight(post, "\n"), DriftNone},
		{"reindented", strings.ReplaceAll(post, "  ", "\t"), DriftNone},
		{"second writer appends after our block",
			strings.Replace(post, "\"_mark1\": \"v1\"}\n", "\"_mark1\": \"v1\"},\n      {\"matcher\": \"\", \"hooks\": [{\"type\": \"command\", \"command\": \"theirs-2\"}]}\n", 1), DriftOutsideFence},
		{"second writer inserts before our block",
			strings.Replace(post, "{\"matcher\": \"\", \"hooks\": [{\"type\": \"command\", \"command\": \"theirs\"}]},", "{\"matcher\": \"\", \"hooks\": [{\"type\": \"command\", \"command\": \"theirs\"}]},\n      {\"matcher\": \"\", \"hooks\": [{\"type\": \"command\", \"command\": \"theirs-0\"}]},", 1), DriftOutsideFence},
		{"user changed a key of theirs", strings.Replace(post, "\"dark\"", "\"light\"", 1), DriftOutsideFence},
		{"user added a top-level key", strings.Replace(post, "\"theme\": \"dark\",", "\"theme\": \"dark\",\n  \"model\": \"x\",", 1), DriftOutsideFence},
		{"user edited inside our entry", strings.Replace(post, "mark1-hookshim", "something-else", 1), DriftInsideFence},
		{"user added a field to our entry", strings.Replace(post, "\"_mark1\": \"v1\"", "\"_mark1\": \"v1\", \"timeout\": 9", 1), DriftInsideFence},
		{"user edited the managed object", strings.Replace(post, "\"version\": 1", "\"version\": 2", 1), DriftInsideFence},
		{"our entries removed", pre, FenceMissing},
		{"only the managed object removed", strings.Replace(post, ",\n  \"_mark1_managed\": {\"version\": 1, \"pointers\": [\"/hooks/Stop/1\"]}", "", 1), DriftInsideFence},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Classify([]byte(pre), []byte(post), []byte(tc.cur))
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestClassifyUnparseableIsFenceMissingWithError(t *testing.T) {
	got, err := Classify([]byte(pre), []byte(post), []byte("{not json"))
	if err == nil || got != FenceMissing {
		t.Fatalf("got %s, %v; want FenceMissing with a parse error", got, err)
	}
}

func TestClassifyNothingFencedIsMissing(t *testing.T) {
	// Mechanism A or a no-op apply: the post image carries nothing of ours.
	got, err := Classify([]byte(pre), []byte(pre), []byte(pre+"\n"))
	if err != nil || got != FenceMissing {
		t.Fatalf("got %s, %v; want FenceMissing", got, err)
	}
}

func TestSplitKeepsTheirEntriesAndOrder(t *testing.T) {
	doc, err := decode([]byte(post))
	if err != nil {
		t.Fatal(err)
	}
	out, ours := Split(doc)
	if len(ours) != 2 {
		t.Fatalf("ours = %d entries, want the tagged hook and the managed object", len(ours))
	}
	stop := out.(map[string]any)["hooks"].(map[string]any)["Stop"].([]any)
	if len(stop) != 1 || stop[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)["command"] != "theirs" {
		t.Fatalf("outside lost or reordered their entry: %v", stop)
	}
	if _, managed := out.(map[string]any)[managedKey]; managed {
		t.Fatal("outside still carries the managed object")
	}
}
