package network

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTLSVersions(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())

	got := TLSVersions(context.Background(), "127.0.0.1", port, "example.com", 2*time.Second)
	if strings.Join(got, ", ") != "TLS 1.1, TLS 1.2" {
		t.Errorf("versions = %v", got)
	}
}
