package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	OK          = "ok"
	Refused     = "refused"
	Timeout     = "timeout"
	Reset       = "reset"
	NoSuchHost  = "no-such-host"
	Unreachable = "unreachable"
	TLSError    = "tls"
	Other       = "error"
	Unknown     = "unknown"
)

type Result struct {
	Class string
	Err   string
	Took  time.Duration
}

func (r Result) OK() bool { return r.Class == OK }

func Classify(err error) string {
	if err == nil {
		return OK
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return Timeout
		}
		return NoSuchHost
	}
	var certErr *tls.CertificateVerificationError
	var hostErr x509.HostnameError
	var unknownCA x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &certErr) || errors.As(err, &hostErr) || errors.As(err, &unknownCA) || errors.As(err, &invalid) {
		return TLSError
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return Refused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, syscall.EPIPE):
		return Reset
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return Unreachable
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return Timeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return Timeout
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection reset"), strings.Contains(msg, "EOF"):
		return Reset
	case strings.Contains(msg, "tls:"), strings.Contains(msg, "x509:"):
		return TLSError
	}
	return Other
}

func result(start time.Time, err error) Result {
	r := Result{Class: Classify(err), Took: time.Since(start)}
	if err != nil {
		r.Err = shortErr(err)
		if r.Class == Timeout {
			r.Err = fmt.Sprintf("timed out after %s", r.Took.Round(100*time.Millisecond))
		}
	}
	return r
}

func shortErr(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		return msg[i+2:]
	}
	return msg
}

func IsLocal(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0", "::", "":
		return true
	}
	return strings.HasPrefix(host, "127.")
}

func Resolve(ctx context.Context, host string, timeout time.Duration) ([]string, Result) {
	start := time.Now()
	if ip := net.ParseIP(host); ip != nil || IsLocal(host) {
		return []string{host}, Result{Class: OK}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	return addrs, result(start, err)
}

func DialTCP(ctx context.Context, host string, port int, timeout time.Duration) Result {
	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(dialHost(host), strconv.Itoa(port)))
	if err == nil {
		c.Close()
	}
	return result(start, err)
}

func DialUnix(ctx context.Context, path string, timeout time.Duration) Result {
	start := time.Now()
	if _, err := os.Stat(path); err != nil {
		return Result{Class: Refused, Err: "socket file does not exist"}
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "unix", path)
	if err == nil {
		c.Close()
	}
	r := result(start, err)
	if errors.Is(err, os.ErrPermission) {
		r.Class, r.Err = OK, "exists (permission denied to connect)"
	}
	return r
}

func dialHost(host string) string {
	switch host {
	case "", "0.0.0.0", "*":
		return "127.0.0.1"
	case "::":
		return "::1"
	}
	return host
}

type HTTPResult struct {
	Result
	Status   int
	Server   string // Server response header
	Location string // redirect target
}

func HTTPGet(ctx context.Context, url, connectHost string, timeout time.Duration) HTTPResult {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if connectHost != "" {
				_, port, _ := net.SplitHostPort(addr)
				addr = net.JoinHostPort(connectHost, port)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		// Certificates are checked separately (CertInfo); here we want to know
		// whether the app answers.
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return HTTPResult{Result: Result{Class: Other, Err: err.Error()}}
	}
	req.Header.Set("User-Agent", "waypoint")
	resp, err := client.Do(req)
	if err != nil {
		return HTTPResult{Result: result(start, err)}
	}
	defer resp.Body.Close()
	io.CopyN(io.Discard, resp.Body, 64<<10)
	return HTTPResult{
		Result:   Result{Class: OK, Took: time.Since(start)},
		Status:   resp.StatusCode,
		Server:   resp.Header.Get("Server"),
		Location: resp.Header.Get("Location"),
	}
}

type Cert struct {
	Subject   string
	Issuer    string
	NotAfter  time.Time
	NameOK    bool   // certificate covers the requested name
	VerifyErr string // chain verification error, if any
}

func (c Cert) DaysLeft() int { return int(time.Until(c.NotAfter).Hours() / 24) }

func CertInfo(ctx context.Context, host string, port int, sni string, timeout time.Duration) (*Cert, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    &tls.Config{ServerName: sni, InsecureSkipVerify: true},
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(dialHost(host), strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificate presented")
	}
	return describeCert(state.PeerCertificates, sni), nil
}

func CertFile(path, name string) (*Cert, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for len(b) > 0 {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, c)
		}
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate in %s", path)
	}
	return describeCert(certs, name), nil
}

func describeCert(chain []*x509.Certificate, name string) *Cert {
	leaf := chain[0]
	c := &Cert{
		Subject:  leaf.Subject.CommonName,
		Issuer:   leaf.Issuer.CommonName,
		NotAfter: leaf.NotAfter,
		NameOK:   name == "" || leaf.VerifyHostname(name) == nil,
	}
	inter := x509.NewCertPool()
	for _, ic := range chain[1:] {
		inter.AddCert(ic)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Intermediates: inter}); err != nil {
		c.VerifyErr = err.Error()
	}
	return c
}
