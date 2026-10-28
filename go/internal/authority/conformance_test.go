package authority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type vectorFile struct {
	Op    string `json:"op"`
	Cases []struct {
		Name     string          `json:"name"`
		Input    json.RawMessage `json:"input"`
		Expected json.RawMessage `json:"expected"`
	} `json:"cases"`
}

// resolve replaces top-level "@name" string values with the shared fixture, keeping key order.
func resolve(t *testing.T, input json.RawMessage, fixtures map[string]json.RawMessage) json.RawMessage {
	dec := json.NewDecoder(bytes.NewReader(input))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return input
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	first := true
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		key := tok.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		var s string
		if json.Unmarshal(v, &s) == nil && strings.HasPrefix(s, "@") {
			f, ok := fixtures[s[1:]]
			if !ok {
				t.Fatalf("unknown fixture %s", s)
			}
			v = f
		}
		if !first {
			buf.WriteByte(',')
		}
		first = false
		k, _ := json.Marshal(key)
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

// decode keeps numbers as their literal text, so 1 and 1.0 are different values.
func decode(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	err := d.Decode(&v)
	return v, err
}

func TestVendoredVectorsMatchLock(t *testing.T) {
	lock, err := ReadLock()
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.Commit) != 40 {
		t.Fatalf("lock commit %q is not a full sha", lock.Commit)
	}
	files, _ := filepath.Glob(filepath.Join("testdata", "vectors", "*.json"))
	if len(files) != len(lock.Vectors.Files) || len(files) == 0 {
		t.Fatalf("%d vector files on disk, %d in the lock", len(files), len(lock.Vectors.Files))
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		sum := sha256.Sum256(b)
		if want := lock.Vectors.Files[filepath.Base(f)]; hex.EncodeToString(sum[:]) != want {
			t.Errorf("%s sha256 does not match the lock", f)
		}
	}
}

func TestAllVectorsMatchPython(t *testing.T) {
	ctx := context.Background()
	core, err := New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close(ctx)

	fb, err := os.ReadFile(filepath.Join("testdata", "vectors", "fixtures.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string]json.RawMessage
	if err := json.Unmarshal(fb, &fixtures); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join("testdata", "vectors", "*.json"))
	sort.Strings(files)
	total, failed := 0, 0
	perOp := map[string]int{}
	for _, f := range files {
		if filepath.Base(f) == "fixtures.json" {
			continue
		}
		b, _ := os.ReadFile(f)
		var vf vectorFile
		if err := json.Unmarshal(b, &vf); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for i, c := range vf.Cases {
			total++
			perOp[vf.Op]++
			req := fmt.Appendf(nil, `{"op":%q,"input":%s}`, vf.Op, resolve(t, c.Input, fixtures))
			out, err := core.Raw(ctx, req)
			if err != nil {
				failed++
				t.Errorf("%s #%d %s: %v", vf.Op, i, c.Name, err)
				continue
			}
			got, err1 := decode(out)
			want, err2 := decode(c.Expected)
			if err1 != nil || err2 != nil || !reflect.DeepEqual(got, want) {
				failed++
				if failed <= 15 {
					t.Errorf("%s #%d %s:\n got  %s\n want %s", vf.Op, i, c.Name, out, c.Expected)
				}
			}
		}
	}
	t.Logf("%d of %d vectors match across %d operations", total-failed, total, len(perOp))
	if total < 5000 {
		t.Fatalf("only %d vectors found", total)
	}
	if failed > 0 {
		t.Fatalf("%d of %d vectors differ", failed, total)
	}
}

func TestBadRequestsFailClosed(t *testing.T) {
	ctx := context.Background()
	core, err := New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close(ctx)
	if _, err := core.Call(ctx, "no_such_op", map[string]any{}); err == nil {
		t.Fatal("unknown op must be an error")
	}
	out, err := core.Raw(ctx, []byte("not json"))
	if err != nil || !bytes.Contains(out, []byte(`"error"`)) {
		t.Fatalf("garbage must come back as an error reply, got %s %v", out, err)
	}
	if _, _, err := core.EvaluateAction(ctx, EvaluateInput{Action: map[string]any{"request_id": "x"}, Policy: json.RawMessage(`{}`), Channel: "nowhere"}); err == nil {
		t.Fatal("unknown channel must be an error")
	}
	// The instance still works after errors.
	if _, err := core.Call(ctx, "canonical", map[string]any{"value": []int{1}}); err != nil {
		t.Fatal(err)
	}
}
