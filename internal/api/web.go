package api

import (
	"embed"
	"io/fs"
	"net/http"
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

// handleIndex serves the single-page UI.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	body, err := fs.ReadFile(assetFS, "index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternal, "UI not available.", "")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The HTML references two hashed-by-hand static files; short caching is
	// enough and keeps upgrades instant.
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(body)
}

// handleStatic serves CSS/JS/logo from the embedded FS with immutable caching.
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
	w.Header().Set("Content-Type", contentTypeFor(name))
	w.Header().Set("Cache-Control", "public, max-age=86400")
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
