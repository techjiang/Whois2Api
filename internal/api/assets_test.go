package api

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// The UI source lives in web/ and is copied into internal/api/assets/ for
// embedding. Two copies of the same file is a bug waiting to happen: someone
// edits web/app.js, the binary keeps serving the old one, and the only symptom
// is "my change did nothing". This test fails the moment they disagree.
func TestEmbeddedAssetsMatchSource(t *testing.T) {
	src := filepath.Join("..", "..", "web")
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("read web/: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		want, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatalf("read web/%s: %v", name, err)
		}
		got, err := fs.ReadFile(assetFS, name)
		if err != nil {
			t.Errorf("embedded asset %q is missing: run `make assets`", name)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("embedded %q differs from web/%s: run `make assets`", name, name)
		}
	}
}
