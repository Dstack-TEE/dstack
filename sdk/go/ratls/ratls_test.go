package ratls_test

import (
	"crypto/tls"
	"fmt"
	"os"
	"testing"

	"github.com/Dstack-TEE/dstack/sdk/go/ratls"
)

// TestVerifyEndpoint connects to a real RA-TLS endpoint and verifies its certificate.
//
// Set RATLS_TEST_ENDPOINT to run this test, e.g.:
//
//	RATLS_TEST_ENDPOINT=myapp-8443s.phala.network:443 go test -v -run TestVerifyEndpoint
func TestVerifyEndpoint(t *testing.T) {
	endpoint := os.Getenv("RATLS_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("RATLS_TEST_ENDPOINT not set")
	}

	pccsURL := os.Getenv("RATLS_PCCS_URL")
	if pccsURL == "" {
		pccsURL = ratls.DefaultPCCSURL
	}

	// Connect with standard TLS (skip CA verification), then verify RA-TLS ourselves
	conn, err := tls.Dial("tcp", endpoint, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS dial failed: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("server presented no certificate")
	}

	cert := state.PeerCertificates[0]
	result, err := ratls.VerifyCert(cert, ratls.WithPCCSURL(pccsURL))
	if err != nil {
		t.Fatalf("RA-TLS verification failed: %v", err)
	}

	t.Logf("verification succeeded")
	t.Logf("  tcb status:  %s", result.Report.Status)
	t.Logf("  advisories:  %v", result.Report.AdvisoryIDs)
	t.Logf("  quote type:  %s", result.Quote.QuoteType)
	t.Logf("  report type: %s", result.Quote.Report.Type)
	if len(result.Quote.Report.RTMR0) > 0 {
		t.Logf("  RTMR0: %x", []byte(result.Quote.Report.RTMR0))
		t.Logf("  RTMR1: %x", []byte(result.Quote.Report.RTMR1))
		t.Logf("  RTMR2: %x", []byte(result.Quote.Report.RTMR2))
		t.Logf("  RTMR3: %x", []byte(result.Quote.Report.RTMR3))
	}
}

// TestTLSConfigEndpoint tests the TLSConfig convenience function against a real endpoint.
func TestTLSConfigEndpoint(t *testing.T) {
	endpoint := os.Getenv("RATLS_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("RATLS_TEST_ENDPOINT not set")
	}

	pccsURL := os.Getenv("RATLS_PCCS_URL")
	if pccsURL == "" {
		pccsURL = ratls.DefaultPCCSURL
	}

	var result *ratls.VerifyResult
	tlsCfg := ratls.TLSConfig(
		ratls.WithPCCSURL(pccsURL),
		ratls.WithOnVerified(func(r *ratls.VerifyResult) {
			result = r
		}),
	)

	conn, err := tls.Dial("tcp", endpoint, tlsCfg)
	if err != nil {
		t.Fatalf("RA-TLS dial failed: %v", err)
	}
	conn.Close()

	if result == nil {
		t.Fatal("OnVerified callback was not called")
	}
	t.Logf("TLSConfig verification succeeded: status=%s", result.Report.Status)
}

// ExampleVerifyCert demonstrates verifying an RA-TLS certificate from a TLS connection.
func ExampleVerifyCert() {
	conn, err := tls.Dial("tcp", "myapp-8443s.phala.network:443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	result, err := ratls.VerifyCert(cert)
	if err != nil {
		fmt.Printf("verification failed: %v\n", err)
		return
	}
	fmt.Printf("verified: status=%s\n", result.Report.Status)
}
