package api

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"sort"
	"strings"
)

// The UI is compiled into the binary: one file to install, one file to back up.
//
//go:embed all:assets
var webAssets embed.FS

// assetFS is the sub-tree containing the UI files.
var assetFS = mustSub(webAssets, "assets")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("api: embedded assets missing: " + err.Error())
	}
	return sub
}

// assetVersion fingerprints every embedded asset at startup.
//
// Without it, a browser caches /static/app.js by name for a day, so replacing
// the binary with a new version kept serving the old UI from cache: the server
// was upgraded, the page was not, and nothing said so. The fingerprint goes into
// the URLs the HTML references, so a new binary means new URLs, while the files
// themselves can stay cacheable for as long as we like.
var assetVersion = computeAssetVersion()

func computeAssetVersion() string {
	h := sha256.New()
	var names []string
	_ = fs.WalkDir(assetFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		names = append(names, path)
		return nil
	})
	sort.Strings(names)
	for _, name := range names {
		body, err := fs.ReadFile(assetFS, name)
		if err != nil {
			continue
		}
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(body)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// handleIndex serves the single-page UI.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	body, err := fs.ReadFile(assetFS, "index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternal, "UI not available.", "")
		return
	}
	// Stamp the asset fingerprint into the static URLs. The HTML itself must
	// never be cached, or the stamp would be stale too.
	html := strings.ReplaceAll(string(body), assetVersionPlaceholder, assetVersion)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(html))
}

// assetVersionPlaceholder is substituted in index.html at serve time.
const assetVersionPlaceholder = "__ASSET_VERSION__"

// handleStatic serves CSS/JS/logo from the embedded FS.
//
// The query string is the cache key: the URL carries a fingerprint of the whole
// asset set, so a long max-age is safe and an upgraded binary is picked up on
// the next page load instead of a day later.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	if name == "" || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	body, err := fs.ReadFile(assetFS, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	h := w.Header()
	h.Set("Content-Type", contentTypeFor(name))
	h.Set("ETag", etag)
	if r.URL.Query().Get("v") == assetVersion {
		// A fingerprinted URL can be cached forever: the name changes when the
		// bytes change.
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		// An unversioned URL (someone hand-typed it, or an old page) must be
		// revalidated so it can never pin a stale file.
		h.Set("Cache-Control", "public, max-age=0, must-revalidate")
	}
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(body)
}

func contentTypeFor(name string) string {
	switch {
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(name, ".png"):
		return "image/png"
	case strings.HasSuffix(name, ".ico"):
		return "image/x-icon"
	case strings.HasSuffix(name, ".webmanifest"):
		return "application/manifest+json"
	default:
		return "application/octet-stream"
	}
}
