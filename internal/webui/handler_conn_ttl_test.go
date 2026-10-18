package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/termcp/internal/sshconfig"
)

const ttlImportDoc = `[[connections]]
name = "injected"
kind = "remote"
host = "sidecar.example"
user = "op"
password = "one-job-secret"
`

func importRequest(t *testing.T, query string) (*httptest.ResponseRecorder, *sshconfig.Store) {
	t.Helper()
	st := sshconfig.NewStore(t.TempDir())
	h := &Handler{SSH: st}
	mux := http.NewServeMux()
	h.Register(mux)
	req := httptest.NewRequest(http.MethodPost, "/api/connections/batch"+query, strings.NewReader(ttlImportDoc))
	out := httptest.NewRecorder()
	mux.ServeHTTP(out, req)
	return out, st
}

func TestImportTemporaryWithTTLExpires(t *testing.T) {
	out, st := importRequest(t, "?temporary=true&ttl_seconds=1")
	if out.Code != http.StatusCreated {
		t.Fatalf("import: %d %s", out.Code, out.Body.String())
	}
	if !st.IsTemporary("injected") {
		t.Fatal("imported profile is not temporary")
	}
	// Poll, never sleep a fixed span: CI runners stall unpredictably.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !st.IsTemporary("injected") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("profile outlived its TTL")
}

func TestImportTTLRejectsNonTemporary(t *testing.T) {
	out, _ := importRequest(t, "?ttl_seconds=60")
	if out.Code != http.StatusBadRequest {
		t.Fatalf("ttl without temporary: got %d, want 400", out.Code)
	}
}

func TestImportTTLValidatesRange(t *testing.T) {
	for _, bad := range []string{"0", "-5", "abc", "99999999"} {
		out, _ := importRequest(t, "?temporary=true&ttl_seconds="+bad)
		if out.Code != http.StatusBadRequest {
			t.Errorf("ttl_seconds=%s: got %d, want 400", bad, out.Code)
		}
	}
}
