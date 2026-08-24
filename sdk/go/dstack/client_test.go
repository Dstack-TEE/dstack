// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
)

func TestGetKey(t *testing.T) {
	client := dstack.NewDstackClient()
	resp, err := client.GetKey(context.Background(), "/", "test", "ed25519")
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}

	if len(resp.SignatureChain) == 0 {
		t.Error("expected certificate chain to not be empty")
	}
}

func TestGetQuote(t *testing.T) {
	client := dstack.NewDstackClient()
	resp, err := client.GetQuote(context.Background(), []byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	if len(resp.Quote) == 0 {
		t.Error("expected quote to not be empty")
	}

	if resp.EventLog == "" {
		t.Error("expected event log to not be empty")
	}

	var eventLog []map[string]interface{}
	err = json.Unmarshal([]byte(resp.EventLog), &eventLog)
	if err != nil {
		t.Errorf("expected event log to be a valid JSON object: %v", err)
	}
}

func TestAttest(t *testing.T) {
	client := dstack.NewDstackClient()
	resp, err := client.Attest(context.Background(), []byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	if len(resp.Attestation) == 0 {
		t.Error("expected attestation to not be empty")
	}

	_, err = client.Attest(context.Background(), bytes.Repeat([]byte("a"), 65))
	if err == nil {
		t.Fatal("expected error for report data larger than 64 bytes")
	}
	if !strings.Contains(err.Error(), "report data is too large") {
		t.Fatalf("expected error to mention report data size, got: %v", err)
	}
}

func TestAttestGpu(t *testing.T) {
	const evidence = `{"result_code":0,"claims":[]}`
	nonce := bytes.Repeat([]byte{0xab}, 32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/AttestGpu" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}
		if payload["nonce"] != hex.EncodeToString(nonce) {
			t.Fatalf("nonce was not forwarded verbatim, got: %v", payload["nonce"])
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"evidence": evidence,
			"nonce":    hex.EncodeToString(nonce),
		})
	}))
	defer server.Close()

	client := dstack.NewDstackClient(dstack.WithEndpoint(server.URL))
	resp, err := client.AttestGpu(context.Background(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Evidence != evidence {
		t.Fatalf("unexpected evidence: %s", resp.Evidence)
	}
	if resp.Nonce != hex.EncodeToString(nonce) {
		t.Fatalf("unexpected nonce: %s", resp.Nonce)
	}
}

func TestAttestGpuRejectsWrongNonceLength(t *testing.T) {
	client := dstack.NewDstackClient()
	for _, n := range [][]byte{nil, bytes.Repeat([]byte{1}, 31), bytes.Repeat([]byte{1}, 33)} {
		if _, err := client.AttestGpu(context.Background(), n); err == nil {
			t.Fatalf("expected a %d-byte nonce to be rejected", len(n))
		}
	}
}

func TestGpuInfo(t *testing.T) {
	const attestation = `{"result_code":0,"claims":[]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/GpuInfo" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"attestation": attestation})
	}))
	defer server.Close()

	client := dstack.NewDstackClient(dstack.WithEndpoint(server.URL))
	response, err := client.GpuInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if response.Attestation != attestation {
		t.Fatalf("unexpected attestation: %s", response.Attestation)
	}
}

func TestGetTlsKey(t *testing.T) {
	client := dstack.NewDstackClient()
	altNames := []string{"localhost"}
	resp, err := client.GetTlsKey(
		context.Background(),
		dstack.WithSubject("test-subject"),
		dstack.WithAltNames(altNames),
		dstack.WithUsageRaTls(true),
		dstack.WithUsageServerAuth(true),
		dstack.WithUsageClientAuth(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}

	if len(resp.CertificateChain) == 0 {
		t.Error("expected certificate chain to not be empty")
	}

	// Verify certificate content
	cert, err := parseCertificate(resp.CertificateChain[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Check subject
	if !strings.Contains(cert.Subject.String(), "test-subject") {
		t.Errorf("expected subject to contain 'test-subject', got %s", cert.Subject.String())
	}

	// Check alt names
	dnsNames := cert.DNSNames

	if len(dnsNames) < 1 || dnsNames[0] != "localhost" {
		t.Errorf("expected DNS name 'localhost', got %v", dnsNames)
	}

	// Check key usage and extended key usage
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("expected KeyUsageDigitalSignature to be set")
	}

	hasServerAuth := false
	hasClientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}

	if !hasServerAuth {
		t.Error("expected ExtKeyUsageServerAuth to be set")
	}

	if !hasClientAuth {
		t.Error("expected ExtKeyUsageClientAuth to be set")
	}
}

func TestGetTlsKeyMinimalOptions(t *testing.T) {
	client := dstack.NewDstackClient()
	// Test with minimal options (just subject)
	resp, err := client.GetTlsKey(
		context.Background(),
		dstack.WithSubject("minimal-subject"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}

	if len(resp.CertificateChain) == 0 {
		t.Error("expected certificate chain to not be empty")
	}

	// Verify certificate content
	cert, err := parseCertificate(resp.CertificateChain[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Check subject
	if !strings.Contains(cert.Subject.String(), "minimal-subject") {
		t.Errorf("expected subject to contain 'minimal-subject', got %s", cert.Subject.String())
	}

	// Check that no alt names are set
	if len(cert.DNSNames) > 0 {
		t.Errorf("expected no DNS names, got %v", cert.DNSNames)
	}

	if len(cert.IPAddresses) > 0 {
		t.Errorf("expected no IP addresses, got %v", cert.IPAddresses)
	}
}

func TestGetTlsKeyServerOnly(t *testing.T) {
	client := dstack.NewDstackClient()
	// Test with server auth only
	resp, err := client.GetTlsKey(
		context.Background(),
		dstack.WithSubject("server-only"),
		dstack.WithUsageServerAuth(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}

	if len(resp.CertificateChain) == 0 {
		t.Error("expected certificate chain to not be empty")
	}

	// Verify certificate content
	cert, err := parseCertificate(resp.CertificateChain[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Check subject
	if !strings.Contains(cert.Subject.String(), "server-only") {
		t.Errorf("expected subject to contain 'server-only', got %s", cert.Subject.String())
	}

	// Check extended key usage
	hasServerAuth := false
	hasClientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}

	if !hasServerAuth {
		t.Error("expected ExtKeyUsageServerAuth to be set")
	}

	if hasClientAuth {
		t.Error("expected ExtKeyUsageClientAuth to not be set")
	}
}

func TestGetTlsKeyClientOnly(t *testing.T) {
	client := dstack.NewDstackClient()
	// Test with client auth only
	resp, err := client.GetTlsKey(
		context.Background(),
		dstack.WithSubject("client-only"),
		dstack.WithUsageClientAuth(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}

	if len(resp.CertificateChain) == 0 {
		t.Error("expected certificate chain to not be empty")
	}

	// Verify certificate content
	cert, err := parseCertificate(resp.CertificateChain[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Check subject
	if !strings.Contains(cert.Subject.String(), "client-only") {
		t.Errorf("expected subject to contain 'client-only', got %s", cert.Subject.String())
	}

	// Check extended key usage
	hasServerAuth := false
	hasClientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}

	if hasServerAuth {
		t.Error("expected ExtKeyUsageServerAuth to not be set")
	}

	if !hasClientAuth {
		t.Error("expected ExtKeyUsageClientAuth to be set")
	}
}

func TestGetTlsKeyWithMultipleAltNames(t *testing.T) {
	client := dstack.NewDstackClient()
	// Test with multiple alternative names
	altNames := []string{"example.com", "test.example.com"}
	resp, err := client.GetTlsKey(
		context.Background(),
		dstack.WithSubject("multi-altnames"),
		dstack.WithAltNames(altNames),
		dstack.WithUsageServerAuth(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}

	if len(resp.CertificateChain) == 0 {
		t.Error("expected certificate chain to not be empty")
	}

	// Verify certificate content
	cert, err := parseCertificate(resp.CertificateChain[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Check subject
	if !strings.Contains(cert.Subject.String(), "multi-altnames") {
		t.Errorf("expected subject to contain 'multi-altnames', got %s", cert.Subject.String())
	}

	// Check DNS names
	expectedDNSNames := []string{"example.com", "test.example.com"}
	for _, name := range expectedDNSNames {
		found := false
		for _, dnsName := range cert.DNSNames {
			if dnsName == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected DNS name %s not found in certificate", name)
		}
	}
}

// Helper function to parse PEM certificate
func parseCertificate(pemCert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

func TestInfo(t *testing.T) {
	client := dstack.NewDstackClient()
	resp, err := client.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if resp.AppID == "" {
		t.Error("expected app_id to not be empty")
	}

	if resp.InstanceID == "" {
		t.Error("expected instance_id to not be empty")
	}

	if resp.TcbInfo == "" {
		t.Error("expected tcb_info to not be empty")
	}

	// Test DecodeTcbInfo
	tcbInfo, err := resp.DecodeTcbInfo()
	if err != nil {
		t.Fatal(err)
	}

	if tcbInfo.Rtmr0 == "" {
		t.Error("expected rtmr0 to not be empty")
	}

	if tcbInfo.Rtmr1 == "" {
		t.Error("expected rtmr1 to not be empty")
	}

	if tcbInfo.Rtmr2 == "" {
		t.Error("expected rtmr2 to not be empty")
	}

	if tcbInfo.Rtmr3 == "" {
		t.Error("expected rtmr3 to not be empty")
	}

	if len(tcbInfo.EventLog) == 0 {
		t.Error("expected event log to not be empty")
	}

	if tcbInfo.ComposeHash == "" {
		t.Error("expected compose_hash to not be empty")
	}

	if tcbInfo.DeviceID == "" {
		t.Error("expected device_id to not be empty")
	}

	if tcbInfo.AppCompose == "" {
		t.Error("expected app_compose to not be empty")
	}
}

func TestSignAndVerifyEd25519(t *testing.T) {
	client := dstack.NewDstackClient()
	dataToSign := []byte("test message for ed25519")
	algorithm := "ed25519"

	signResp, err := client.Sign(context.Background(), algorithm, dataToSign)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if len(signResp.Signature) == 0 {
		t.Error("expected signature to not be empty")
	}
	if len(signResp.PublicKey) == 0 {
		t.Error("expected public key to not be empty")
	}
	if len(signResp.SignatureChain) != 3 {
		t.Errorf("expected signature chain to have 3 elements, got %d", len(signResp.SignatureChain))
	}
	if !bytes.Equal(signResp.Signature, signResp.SignatureChain[0]) {
		t.Error("expected Signature to be the same as SignatureChain[0]")
	}

	// Verification is local: it needs no key material, so the SDK checks the
	// signature itself rather than asking the agent for an unattested verdict.
	valid, err := dstack.VerifySignature(algorithm, dataToSign, signResp.Signature, signResp.PublicKey)
	if err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}

	if !valid {
		t.Error("expected verification to be valid")
	}

	badData := []byte("wrong message")
	valid, err = dstack.VerifySignature(algorithm, badData, signResp.Signature, signResp.PublicKey)
	if err != nil {
		t.Fatalf("VerifySignature() with bad data error = %v", err)
	}

	if valid {
		t.Error("expected verification with bad data to be invalid")
	}
}

func TestSignAndVerifySecp256k1(t *testing.T) {
	client := dstack.NewDstackClient()
	dataToSign := []byte("test message for secp256k1")
	algorithm := "secp256k1"

	signResp, err := client.Sign(context.Background(), algorithm, dataToSign)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if len(signResp.Signature) == 0 {
		t.Error("expected signature to not be empty")
	}
	if len(signResp.PublicKey) == 0 {
		t.Error("expected public key to not be empty")
	}
	if len(signResp.SignatureChain) != 3 {
		t.Errorf("expected signature chain to have 3 elements, got %d", len(signResp.SignatureChain))
	}

	valid, err := dstack.VerifySignature(algorithm, dataToSign, signResp.Signature, signResp.PublicKey)
	if err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}

	if !valid {
		t.Error("expected verification to be valid")
	}

	// The chain is what actually ties the signing key back to a KMS root; a bare
	// signature only proves whoever holds signResp.PublicKey signed the payload.
	if !bytes.Equal(signResp.Signature, signResp.SignatureChain[0]) {
		t.Error("expected Signature to be the same as SignatureChain[0]")
	}
}

func TestSignAndVerifySecp256k1Prehashed(t *testing.T) {
	client := dstack.NewDstackClient()
	dataToSign := []byte("test message for secp256k1 prehashed")
	digest := sha256.Sum256(dataToSign)
	algorithm := "secp256k1_prehashed"

	signResp, err := client.Sign(context.Background(), algorithm, digest[:])
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if len(signResp.Signature) == 0 {
		t.Error("expected signature to not be empty")
	}

	valid, err := dstack.VerifySignature(algorithm, digest[:], signResp.Signature, signResp.PublicKey)
	if err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}

	if !valid {
		t.Error("expected verification to be valid")
	}

	// A pre-hashed digest must be exactly 32 bytes on the verifying side too.
	if _, err := dstack.VerifySignature(algorithm, dataToSign, signResp.Signature, signResp.PublicKey); err == nil {
		t.Error("expected VerifySignature to reject a non-digest payload for secp256k1_prehashed")
	}

	// Test invalid digest length for signing
	invalidDigest := []byte{1, 2, 3}
	_, err = client.Sign(context.Background(), algorithm, invalidDigest)
	if err == nil {
		t.Fatal("expected error for invalid digest length, got nil")
	}
	if !strings.Contains(err.Error(), "32-byte digest") {
		t.Errorf("expected error to mention '32-byte digest', got: %v", err)
	}
}

func TestGetVersion(t *testing.T) {
	client := dstack.NewDstackClient()
	resp, err := client.GetVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if resp.Version == "" {
		t.Error("expected version to not be empty")
	}
}

func TestGetKeyK256Alias(t *testing.T) {
	client := dstack.NewDstackClient()

	respK256, err := client.GetKey(context.Background(), "/test", "purpose", "k256")
	if err != nil {
		t.Fatal(err)
	}

	respSecp, err := client.GetKey(context.Background(), "/test", "purpose", "secp256k1")
	if err != nil {
		t.Fatal(err)
	}

	// k256 is an alias for secp256k1, should produce the same key
	if respK256.Key != respSecp.Key {
		t.Error("expected k256 and secp256k1 to produce the same key")
	}
}

func TestGetKeyUnsupportedAlgorithm(t *testing.T) {
	client := dstack.NewDstackClient()
	_, err := client.GetKey(context.Background(), "/test", "purpose", "rsa")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestGetKeySecp256k1PrehashedRejected(t *testing.T) {
	client := dstack.NewDstackClient()
	_, err := client.GetKey(context.Background(), "/test", "purpose", "secp256k1_prehashed")
	if err == nil {
		t.Fatal("expected error for secp256k1_prehashed in GetKey")
	}
}

func TestGetKeyAlgorithmValidation(t *testing.T) {
	client := dstack.NewDstackClient()

	// ed25519 should succeed (Version RPC is available on the simulator)
	resp, err := client.GetKey(context.Background(), "/test", "purpose", "ed25519")
	if err != nil {
		t.Fatalf("expected ed25519 to succeed: %v", err)
	}
	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}
}
