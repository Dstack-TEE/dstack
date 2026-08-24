// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
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

// The frozen surface is exactly v0.5.11, so v0's Attest must keep sending the
// v0.5.11 request body. The GPU flag belongs to v1 and must not leak back here.
func TestAttestRequestIsFrozenAtV0(t *testing.T) {
	var payload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Attest" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"attestation": "deadbeef"})
	}))
	defer server.Close()

	client := dstack.NewDstackClientV0(dstack.WithEndpoint(server.URL))
	resp, err := client.Attest(context.Background(), []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resp.Attestation, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("unexpected attestation: %x", resp.Attestation)
	}
	if len(payload) != 1 {
		t.Errorf("expected report_data to be the only request field, got %v", payload)
	}
	if _, present := payload["include_boottime_gpu_evidence"]; present {
		t.Error("include_boottime_gpu_evidence is a v1 field and must not appear on the frozen surface")
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

	verifyResp, err := client.Verify(context.Background(), algorithm, dataToSign, signResp.Signature, signResp.PublicKey)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !verifyResp.Valid {
		t.Error("expected verification to be valid")
	}

	badData := []byte("wrong message")
	verifyResp, err = client.Verify(context.Background(), algorithm, badData, signResp.Signature, signResp.PublicKey)
	if err != nil {
		t.Fatalf("Verify() with bad data error = %v", err)
	}

	if verifyResp.Valid {
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

	verifyResp, err := client.Verify(context.Background(), algorithm, dataToSign, signResp.Signature, signResp.PublicKey)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !verifyResp.Valid {
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

	verifyResp, err := client.Verify(context.Background(), algorithm, digest[:], signResp.Signature, signResp.PublicKey)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !verifyResp.Valid {
		t.Error("expected verification to be valid")
	}

	// The signature covers the digest, so the raw payload it was taken over does
	// not verify: secp256k1_prehashed treats data as the digest itself.
	verifyResp, err = client.Verify(context.Background(), algorithm, dataToSign, signResp.Signature, signResp.PublicKey)
	if err != nil {
		t.Fatalf("Verify() with a non-digest payload error = %v", err)
	}
	if verifyResp.Valid {
		t.Error("expected a non-digest payload not to verify under secp256k1_prehashed")
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

// EmitEvent is gone from the agent as of 0.6.0, but it stays on the client so a
// pre-0.6 application still compiles. The agent's removal message must reach the
// caller verbatim: an application that thinks it measured something it did not
// is worse off than one that fails loudly.
func TestEmitEventSurfacesTheRemovalMessage(t *testing.T) {
	client := dstack.NewDstackClientV0()
	err := client.EmitEvent(context.Background(), "test-event", []byte("payload"))
	if err == nil {
		t.Fatal("expected EmitEvent to fail against a 0.6.0 agent")
	}
	if !strings.Contains(err.Error(), "EmitEvent was removed in dstack 0.6.0") {
		t.Errorf("expected the agent's removal message to be surfaced, got: %v", err)
	}

	// The client-side guard still runs first, so an empty name never reaches the wire.
	if err := client.EmitEvent(context.Background(), "", nil); err == nil {
		t.Error("expected an empty event name to be rejected")
	}
}

// NewDstackClient is kept as a deprecated alias for NewDstackClientV0, so code
// written against the pre-0.6 SDK keeps compiling and keeps talking to the same
// frozen surface.
func TestDeprecatedAliasIsTheV0Client(t *testing.T) {
	var client *dstack.DstackClientV0 = dstack.NewDstackClient()
	if !client.IsReachable(context.Background()) {
		t.Error("expected the aliased client to reach the simulator")
	}
}
