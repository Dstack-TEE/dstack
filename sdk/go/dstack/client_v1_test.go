// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// Exercises DstackClientV1 against the simulator, which serves the real v1
// handlers -- so these tests pin the wire encoding, not a hand-written mock.

package dstack_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
)

func TestV1Version(t *testing.T) {
	client := dstack.NewDstackClientV1()
	resp, err := client.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if resp.Version == "" {
		t.Error("expected version to not be empty")
	}
}

func TestV1GetKey(t *testing.T) {
	client := dstack.NewDstackClientV1()

	for _, tc := range []struct {
		algorithm string
		pubKeyLen int
	}{
		{"secp256k1", 33},
		{"ed25519", 32},
	} {
		resp, err := client.GetKey(context.Background(), "wallet", tc.algorithm)
		if err != nil {
			t.Fatalf("%s: %v", tc.algorithm, err)
		}

		if len(resp.Key) != 32 {
			t.Errorf("%s: expected a 32-byte key, got %d", tc.algorithm, len(resp.Key))
		}
		if len(resp.PublicKey) != tc.pubKeyLen {
			t.Errorf("%s: expected a %d-byte public key, got %d", tc.algorithm, tc.pubKeyLen, len(resp.PublicKey))
		}
		// [0] the app root key over the v1 key claim, [1] the KMS root key over
		// the app root public key.
		if len(resp.SignatureChain) != 2 {
			t.Errorf("%s: expected 2 chain links, got %d", tc.algorithm, len(resp.SignatureChain))
		}
		for i, link := range resp.SignatureChain {
			if len(link) != 65 {
				t.Errorf("%s: chain link %d is %d bytes, want a 65-byte recoverable signature",
					tc.algorithm, i, len(link))
			}
		}
	}
}

// v1 binds the algorithm into the derivation, so the two curves no longer share
// one 32-byte secret the way they did on the frozen surface.
func TestV1GetKeyIsDomainSeparated(t *testing.T) {
	client := dstack.NewDstackClientV1()
	ctx := context.Background()

	k256, err := client.GetKey(ctx, "wallet", "secp256k1")
	if err != nil {
		t.Fatal(err)
	}
	ed, err := client.GetKey(ctx, "wallet", "ed25519")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k256.Key, ed.Key) {
		t.Error("expected the algorithm to be bound into the derivation")
	}

	other, err := client.GetKey(ctx, "other", "secp256k1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k256.Key, other.Key) {
		t.Error("expected two domains to yield unrelated keys")
	}

	// Derivation is stable for a given (domain, algorithm).
	again, err := client.GetKey(ctx, "wallet", "secp256k1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k256.Key, again.Key) {
		t.Error("expected the same domain and algorithm to derive the same key")
	}
}

// v1 keys are not v0 keys, so a caller cannot migrate a name across surfaces and
// expect the same material back. Nothing in the SDK smooths this over.
func TestV1GetKeyDiffersFromV0(t *testing.T) {
	ctx := context.Background()

	v1Resp, err := dstack.NewDstackClientV1().GetKey(ctx, "wallet", "secp256k1")
	if err != nil {
		t.Fatal(err)
	}
	v0Resp, err := dstack.NewDstackClientV0().GetKey(ctx, "wallet", "", "secp256k1")
	if err != nil {
		t.Fatal(err)
	}
	v0Key, err := v0Resp.DecodeKey()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(v1Resp.Key, v0Key) {
		t.Error("v1 must derive different key material than v0 for the same name")
	}
}

// The algorithm is required and has no alias: v1 refuses to guess what a caller
// meant rather than handing back a key of a type they did not ask for.
func TestV1GetKeyRejectsMissingOrUnknownAlgorithms(t *testing.T) {
	client := dstack.NewDstackClientV1()
	ctx := context.Background()

	_, err := client.GetKey(ctx, "wallet", "")
	if err == nil {
		t.Fatal("expected an empty algorithm to be rejected")
	}
	if !strings.Contains(err.Error(), "algorithm is required") {
		t.Errorf("expected the error to name the missing algorithm, got: %v", err)
	}

	// Rejected client-side, so this never reaches the wire.
	if strings.Contains(err.Error(), "unexpected status code") {
		t.Error("expected the empty algorithm to be caught before the request was sent")
	}

	for _, algorithm := range []string{"k256", "secp256k1_prehashed", "rsa"} {
		if _, err := client.GetKey(ctx, "wallet", algorithm); err == nil {
			t.Errorf("expected algorithm %q to be rejected", algorithm)
		}
	}
}

func TestV1Attest(t *testing.T) {
	client := dstack.NewDstackClientV1()
	resp, err := client.Attest(context.Background(), []byte("test"), false)
	if err != nil {
		t.Fatal(err)
	}

	if len(resp.Attestation) == 0 {
		t.Error("expected attestation to not be empty")
	}
}

func TestV1AttestRejectsBadReportDataLengths(t *testing.T) {
	client := dstack.NewDstackClientV1()
	for _, reportData := range [][]byte{nil, {}, bytes.Repeat([]byte("a"), 65)} {
		if _, err := client.Attest(context.Background(), reportData, false); err == nil {
			t.Errorf("expected %d bytes of report data to be rejected", len(reportData))
		}
	}
}

// The simulator has no GPU, so the round trip cannot succeed here. What can be
// pinned is the request encoding and the client-side nonce rule.
func TestV1AttestGpu(t *testing.T) {
	nonce := bytes.Repeat([]byte{0xab}, 32)

	var payload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/AttestGpu" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"bundles": []map[string]string{{
				"vendor": "nvidia", "format": "nvidia-nras-v1", "evidence": "deadbeef",
			}},
		})
	}))
	defer server.Close()

	client := dstack.NewDstackClientV1(dstack.WithEndpoint(server.URL))
	resp, err := client.AttestGpu(context.Background(), nonce)
	if err != nil {
		t.Fatal(err)
	}

	// Passed through verbatim, so a caller can compare it against eat_nonce.
	if payload["nonce"] != "abababababababababababababababababababababababababababababababab" {
		t.Errorf("nonce was not forwarded verbatim, got: %v", payload["nonce"])
	}
	if len(resp.Bundles) != 1 {
		t.Fatalf("expected 1 bundle, got %d", len(resp.Bundles))
	}
	if resp.Bundles[0].Vendor != "nvidia" || resp.Bundles[0].Format != "nvidia-nras-v1" {
		t.Errorf("unexpected bundle: %+v", resp.Bundles[0])
	}
	if !bytes.Equal(resp.Bundles[0].Evidence, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("expected hex-decoded evidence, got %x", resp.Bundles[0].Evidence)
	}
}

func TestV1AttestGpuRejectsWrongNonceLength(t *testing.T) {
	client := dstack.NewDstackClientV1()
	for _, nonce := range [][]byte{nil, bytes.Repeat([]byte{1}, 31), bytes.Repeat([]byte{1}, 33)} {
		if _, err := client.AttestGpu(context.Background(), nonce); err == nil {
			t.Errorf("expected a %d-byte nonce to be rejected", len(nonce))
		}
	}
}

func TestV1Info(t *testing.T) {
	client := dstack.NewDstackClientV1()
	resp, err := client.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(resp.AppID) == 0 {
		t.Error("expected app_id to not be empty")
	}
	if len(resp.InstanceID) == 0 {
		t.Error("expected instance_id to not be empty")
	}
	if resp.AppName == "" {
		t.Error("expected app_name to not be empty")
	}
	if len(resp.DeviceID) != 32 {
		t.Errorf("expected a 32-byte device_id, got %d", len(resp.DeviceID))
	}
	if len(resp.ComposeHash) != 32 {
		t.Errorf("expected a 32-byte compose_hash, got %d", len(resp.ComposeHash))
	}
	if len(resp.MrAggregated) != 32 {
		t.Errorf("expected a 32-byte mr_aggregated, got %d", len(resp.MrAggregated))
	}
	if len(resp.OsImageHash) != 32 {
		t.Errorf("expected a 32-byte os_image_hash, got %d", len(resp.OsImageHash))
	}

	// The document fields are served directly, not nested in a JSON string.
	var appCompose map[string]interface{}
	if err := json.Unmarshal([]byte(resp.AppCompose), &appCompose); err != nil {
		t.Errorf("expected app_compose to be a JSON document: %v", err)
	}
	var vmConfig map[string]interface{}
	if err := json.Unmarshal([]byte(resp.VmConfig), &vmConfig); err != nil {
		t.Errorf("expected vm_config to be a JSON document: %v", err)
	}
	var keyProviderInfo map[string]interface{}
	if err := json.Unmarshal([]byte(resp.KeyProviderInfo), &keyProviderInfo); err != nil {
		t.Errorf("expected key_provider_info to be a JSON document: %v", err)
	}
}

func TestV1IssueCert(t *testing.T) {
	client := dstack.NewDstackClientV1()
	resp, err := client.IssueCert(
		context.Background(),
		dstack.WithCertSubject("test-subject"),
		dstack.WithCertAltNames([]string{"localhost"}),
		dstack.WithCertUsageServerAuth(true),
		dstack.WithCertUsageClientAuth(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}
	if len(resp.CertificateChain) == 0 {
		t.Fatal("expected certificate chain to not be empty")
	}

	cert, err := parseCertificate(resp.CertificateChain[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	if !strings.Contains(cert.Subject.String(), "test-subject") {
		t.Errorf("expected subject to contain 'test-subject', got %s", cert.Subject.String())
	}
	if len(cert.DNSNames) < 1 || cert.DNSNames[0] != "localhost" {
		t.Errorf("expected DNS name 'localhost', got %v", cert.DNSNames)
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

// The key is generated per call and is not derived from the app identity, so
// two identical requests must not return the same key.
func TestV1IssueCertKeyIsFreshPerCall(t *testing.T) {
	client := dstack.NewDstackClientV1()
	ctx := context.Background()

	first, err := client.IssueCert(ctx, dstack.WithCertSubject("same"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.IssueCert(ctx, dstack.WithCertSubject("same"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Key == second.Key {
		t.Error("expected IssueCert to generate a fresh key on every call")
	}
}

// Version selection is by URL path alone: every v1 method must post under /v1.
func TestV1MethodsPostUnderTheV1Prefix(t *testing.T) {
	paths := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"bundles":[]}`))
	}))
	defer server.Close()

	client := dstack.NewDstackClientV1(dstack.WithEndpoint(server.URL))
	ctx := context.Background()

	calls := []struct {
		want string
		call func() error
	}{
		{"/v1/IssueCert", func() error { _, err := client.IssueCert(ctx); return err }},
		{"/v1/GetKey", func() error { _, err := client.GetKey(ctx, "d", "ed25519"); return err }},
		{"/v1/Attest", func() error { _, err := client.Attest(ctx, []byte("x"), false); return err }},
		{"/v1/AttestGpu", func() error {
			_, err := client.AttestGpu(ctx, bytes.Repeat([]byte{0}, 32))
			return err
		}},
		{"/v1/Info", func() error { _, err := client.Info(ctx); return err }},
		{"/v1/Version", func() error { _, err := client.Version(ctx); return err }},
	}

	for _, c := range calls {
		if err := c.call(); err != nil {
			t.Fatalf("%s: %v", c.want, err)
		}
		if got := <-paths; got != c.want {
			t.Errorf("expected %s, got %s", c.want, got)
		}
	}
}

// An agent that predates v1 has no /v1 mount, so it answers with a plain 404
// rather than a prpc error. The client surfaces that rather than masking it.
func TestV1AgainstAnAgentWithoutV1(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "404 Not Found", http.StatusNotFound)
	}))
	defer server.Close()

	client := dstack.NewDstackClientV1(dstack.WithEndpoint(server.URL))
	_, err := client.Version(context.Background())
	if err == nil {
		t.Fatal("expected a 404 from an agent without a v1 mount to be an error")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("expected the status to be reported, got: %v", err)
	}
}
