// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"crypto/x509"
	"encoding/pem"

	"crypto/ecdsa"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestGetKey(t *testing.T) {
	client := dstack.NewDstackClient()
	resp, err := client.GetKey(context.Background(), "/", "test")
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

	// Get quote RTMRs manually
	quoteRtmrs := [4][48]byte{
		[48]byte(resp.Quote[376:424]),
		[48]byte(resp.Quote[424:472]),
		[48]byte(resp.Quote[472:520]),
		[48]byte(resp.Quote[520:568]),
	}

	// Test ReplayRTMRs
	rtmrs, err := resp.ReplayRTMRs()
	if err != nil {
		t.Fatal(err)
	}

	if len(rtmrs) != 4 {
		t.Errorf("expected 4 RTMRs, got %d", len(rtmrs))
	}

	// Verify RTMRs
	for i := 0; i < 4; i++ {
		if rtmrs[i] == "" {
			t.Errorf("expected RTMR %d to not be empty", i)
		}

		rtmrBytes, err := hex.DecodeString(rtmrs[i])
		if err != nil {
			t.Errorf("expected RTMR %d to be valid hex: %v", i, err)
		}

		if !bytes.Equal(rtmrBytes, quoteRtmrs[i][:]) {
			t.Errorf("expected RTMR %d to be %s, got %s", i, hex.EncodeToString(quoteRtmrs[i][:]), rtmrs[i])
		}
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

func TestGetKeySignatureVerification(t *testing.T) {
	expectedAppPubkey, _ := hex.DecodeString("02b85cceca0c02d878f0ebcda72a97469a472416eb6faf3c4807642132f9786810")
	expectedKmsPubkey, _ := hex.DecodeString("02cad3a8bb11c5c0858fb3e402048b5137457039d577986daade678ed4b4ab1b9b")

	client := dstack.NewDstackClient()
	path := "/test/path"
	purpose := "test-purpose"
	resp, err := client.GetKey(context.Background(), path, purpose)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}

	if len(resp.SignatureChain) != 2 {
		t.Fatalf("expected signature chain to have 2 elements, got %d", len(resp.SignatureChain))
	}

	// Extract the app signature and KMS signature from the chain
	appSignatureHex := resp.SignatureChain[0]
	kmsSignatureHex := resp.SignatureChain[1]

	// Convert hex strings to bytes
	appSignature, err := hex.DecodeString(appSignatureHex)
	if err != nil {
		t.Fatalf("failed to decode app signature: %v", err)
	}

	kmsSignature, err := hex.DecodeString(kmsSignatureHex)
	if err != nil {
		t.Fatalf("failed to decode KMS signature: %v", err)
	}

	// Verify signatures have the correct format (signature + recovery ID)
	if len(appSignature) != 65 {
		t.Errorf("expected app signature to be 65 bytes (64 bytes signature + 1 byte recovery ID), got %d", len(appSignature))
	}

	if len(kmsSignature) != 65 {
		t.Errorf("expected KMS signature to be 65 bytes (64 bytes signature + 1 byte recovery ID), got %d", len(kmsSignature))
	}

	// Get app info to retrieve app ID for verification
	infoResp, err := client.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// 1. Derive the public key from the private key
	derivedPrivKey := resp.Key
	derivedPubKey, err := derivePublicKeyFromPrivate(derivedPrivKey)
	if err != nil {
		t.Fatalf("failed to derive public key: %v", err)
	}

	// 2. Construct the message that was signed
	message := fmt.Sprintf("%s:%s", purpose, hex.EncodeToString(derivedPubKey))

	// 3. Recover the app's public key from the signature
	appPubKey, err := recoverPublicKey(message, appSignature)
	if err != nil {
		t.Fatalf("failed to recover app public key: %v", err)
	}

	// Convert the recovered public key to compressed format for comparison
	appPubKeyCompressed, err := compressPublicKey(appPubKey)
	if err != nil {
		t.Fatalf("failed to compress recovered public key: %v", err)
	}

	if !bytes.Equal(appPubKeyCompressed, expectedAppPubkey) {
		t.Errorf("app public key mismatch:\nExpected: %s\nActual:   %s",
			hex.EncodeToString(expectedAppPubkey),
			hex.EncodeToString(appPubKeyCompressed))
	}

	// 4. Verify the app ID matches what we expect
	// The app ID should be derivable from the app's public key
	// or should match what's returned from the Info endpoint
	appIDFromInfo, err := hex.DecodeString(infoResp.AppID)
	if err != nil {
		t.Fatalf("failed to decode app ID: %v", err)
	}

	// 5. Construct the message that KMS would have signed
	// This would typically be something like "dstack-kms-issued:{app_id}{app_public_key}"
	kmsMessage := fmt.Sprintf("dstack-kms-issued:%s%s", appIDFromInfo, string(appPubKeyCompressed))
	kmsPubKey, err := recoverPublicKey(kmsMessage, kmsSignature)
	if err != nil {
		t.Fatalf("failed to recover KMS public key: %v", err)
	}

	kmsPubKeyCompressed, err := compressPublicKey(kmsPubKey)
	if err != nil {
		t.Fatalf("failed to compress KMS public key: %v", err)
	}

	if !bytes.Equal(kmsPubKeyCompressed, expectedKmsPubkey) {
		t.Errorf("KMS public key mismatch:\nExpected: %s\nActual:   %s",
			hex.EncodeToString(expectedKmsPubkey),
			hex.EncodeToString(kmsPubKeyCompressed))
	}

	// Verify that the recovered app public key can verify the app signature
	verified, err := verifySignature(message, appSignature, appPubKey)
	if err != nil {
		t.Fatalf("signature verification error: %v", err)
	}
	if !verified {
		t.Error("app signature verification failed")
	}
}

// Helper function to derive a public key from a private key
func derivePublicKeyFromPrivate(privateKeyHex string) ([]byte, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	// Import the private key
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to ECDSA private key: %w", err)
	}

	// Derive the public key in compressed format
	publicKey := crypto.CompressPubkey(&privateKey.PublicKey)
	return publicKey, nil
}

// Helper function to recover a public key from a signature
func recoverPublicKey(message string, signature []byte) ([]byte, error) {
	if len(signature) != 65 {
		return nil, fmt.Errorf("invalid signature length: expected 65 bytes, got %d", len(signature))
	}

	// Hash the message using Keccak256
	messageHash := crypto.Keccak256([]byte(message))

	// Recover the public key
	pubKey, err := crypto.Ecrecover(messageHash, signature)
	if err != nil {
		return nil, fmt.Errorf("failed to recover public key: %w", err)
	}

	return pubKey, nil
}

// Helper function to verify a signature
func verifySignature(message string, signature []byte, publicKey []byte) (bool, error) {
	if len(signature) != 65 {
		return false, fmt.Errorf("invalid signature length: expected 65 bytes, got %d", len(signature))
	}

	// Hash the message using Keccak256
	messageHash := crypto.Keccak256([]byte(message))

	// The last byte is the recovery ID, we need to remove it for verification
	signatureWithoutRecoveryID := signature[:64]

	// Verify the signature
	return crypto.VerifySignature(publicKey, messageHash, signatureWithoutRecoveryID), nil
}

// Add this helper function to compress a public key
func compressPublicKey(uncompressedKey []byte) ([]byte, error) {
	if len(uncompressedKey) < 65 || uncompressedKey[0] != 4 {
		return nil, fmt.Errorf("invalid uncompressed public key")
	}
	x := new(big.Int).SetBytes(uncompressedKey[1:33])
	y := new(big.Int).SetBytes(uncompressedKey[33:65])
	pubKey := &ecdsa.PublicKey{
		Curve: crypto.S256(),
		X:     x,
		Y:     y,
	}
	return crypto.CompressPubkey(pubKey), nil
}
