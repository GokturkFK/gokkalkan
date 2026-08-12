package transport

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestCanonicalPath(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    string
		wantErr error
	}{
		{"duz yol", "/repos/foo", "/repos/foo", nil},
		{"bos yol koke duser", "", "/", nil},
		{"cift slash sadelesir", "/repos//foo", "/repos/foo", nil},
		{"nokta sadelesir", "/repos/./foo", "/repos/foo", nil},
		{"traversal cozulur", "/repos/../admin", "/admin", nil},
		// Go url.Parse tek kez decode eder: %2e%2e -> ".." (duz karaktere doner,
		// path.Clean cozer). Cift encode edilmis girdi decode sonrasi hala
		// metakarakter tasir -> reddedilir.
		{"tek encode decode edilip normalize edilir", "/repos/%2e%2e/admin", "/admin", nil},
		{"cift encode reddedilir", "/repos/%252e%252e/admin", "", ErrAmbiguousPath},
		{"ters boluk reddedilir", "/repos/..\\admin", "", ErrAmbiguousPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse("http://example.com" + tc.raw)
			if err != nil {
				t.Fatalf("test URL parse edilemedi: %v", err)
			}
			got, err := CanonicalPath(u)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("hata = %v, istenen %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("beklenmeyen hata: %v", err)
			}
			if got != tc.want {
				t.Errorf("CanonicalPath(%q) = %q, istenen %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestFromRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://api.github.com:443/repos/../admin", nil)
	r.Header.Set(HeaderAgentID, "agent-1")

	req, err := FromRequest(r)
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if req.AgentID != "agent-1" {
		t.Errorf("AgentID = %q", req.AgentID)
	}
	if req.Method != http.MethodGet {
		t.Errorf("Method = %q", req.Method)
	}
	// Port allowlist eslesmesine girmemeli.
	if req.Host != "api.github.com" {
		t.Errorf("Host = %q, port ayiklanmaliydi", req.Host)
	}
	// Karar katmani KANONIK yolu gormeli, ham "/repos/../admin" degil.
	if req.Path != "/admin" {
		t.Errorf("Path = %q, istenen /admin (normalize edilmis)", req.Path)
	}
}

func TestFromRequest_MissingAgentID(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://api.github.com/repos", nil)
	if _, err := FromRequest(r); !errors.Is(err, ErrMissingAgentID) {
		t.Fatalf("hata = %v, ErrMissingAgentID bekleniyordu", err)
	}
}

func TestFromRequest_AmbiguousPathRejected(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://api.github.com/repos/%252e%252e/admin", nil)
	r.Header.Set(HeaderAgentID, "agent-1")
	if _, err := FromRequest(r); !errors.Is(err, ErrAmbiguousPath) {
		t.Fatalf("hata = %v, ErrAmbiguousPath bekleniyordu", err)
	}
}
