// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// Drives the shared cross-SDK vectors in `sdk/tests/vectors/signature_chain.json`.
// The Rust, Python and JavaScript suites assert against the same file, so any port
// that disagrees about the byte format fails here too.

package dstack_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
)

const vectorsPath = "../../tests/vectors/signature_chain.json"

type vectorCase struct {
	Algorithm      string   `json:"algorithm"`
	Data           string   `json:"data"`
	PublicKey      string   `json:"public_key"`
	Signature      string   `json:"signature"`
	SignatureChain []string `json:"signature_chain"`
	Name           string   `json:"name"`
	Reason         string   `json:"reason"`
}

type vectorFile struct {
	AppID              string       `json:"app_id"`
	Purpose            string       `json:"purpose"`
	Path               string       `json:"path"`
	KMSRootPubKey      string       `json:"kms_root_pubkey"`
	AppRootPubKey      string       `json:"app_root_pubkey"`
	WrongKMSRootPubKey string       `json:"wrong_kms_root_pubkey"`
	Cases              []vectorCase `json:"cases"`
	InvalidCases       []vectorCase `json:"invalid_cases"`
}

func vectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(v.Cases) == 0 || len(v.InvalidCases) == 0 {
		t.Fatalf("vectors file has no cases")
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	return b
}

func chainOf(t *testing.T, c vectorCase) [][]byte {
	t.Helper()
	chain := make([][]byte, len(c.SignatureChain))
	for i, s := range c.SignatureChain {
		chain[i] = unhex(t, s)
	}
	return chain
}

func caseWithAlgorithm(t *testing.T, v vectorFile, algorithm string) vectorCase {
	t.Helper()
	for _, c := range v.Cases {
		if c.Algorithm == algorithm {
			return c
		}
	}
	t.Fatalf("no vector case for algorithm %q", algorithm)
	return vectorCase{}
}

func TestVerifySignatureValidVectors(t *testing.T) {
	v := vectors(t)
	for _, c := range v.Cases {
		valid, err := dstack.VerifySignature(
			c.Algorithm, unhex(t, c.Data), unhex(t, c.Signature), unhex(t, c.PublicKey))
		if err != nil {
			t.Fatalf("%s: %v", c.Algorithm, err)
		}
		if !valid {
			t.Errorf("%s: valid signature was rejected", c.Algorithm)
		}
	}
}

func TestVerifySignatureInvalidVectors(t *testing.T) {
	v := vectors(t)
	for _, c := range v.InvalidCases {
		valid, err := dstack.VerifySignature(
			c.Algorithm, unhex(t, c.Data), unhex(t, c.Signature), unhex(t, c.PublicKey))
		// High-S is refused outright rather than reported false, because it is a
		// malformed encoding rather than a legitimate signature that fails to match.
		if err != nil {
			if c.Name != "secp256k1_high_s" {
				t.Errorf("%s: unexpected error %v", c.Name, err)
			}
			continue
		}
		if valid {
			t.Errorf("%s: should not have verified (%s)", c.Name, c.Reason)
		}
	}
}

func TestVerifySignatureHighSIsRejected(t *testing.T) {
	v := vectors(t)
	var found bool
	for _, c := range v.InvalidCases {
		if c.Name != "secp256k1_high_s" {
			continue
		}
		found = true
		valid, err := dstack.VerifySignature(
			c.Algorithm, unhex(t, c.Data), unhex(t, c.Signature), unhex(t, c.PublicKey))
		if err == nil {
			t.Fatalf("high-S signature was accepted as an encoding (valid=%v)", valid)
		}
		if !strings.Contains(err.Error(), "high-S") {
			t.Errorf("unexpected error for high-S: %v", err)
		}
	}
	if !found {
		t.Fatal("vectors file no longer pins the secp256k1_high_s case")
	}
}

func TestVerifySignatureK256IsAnAliasForSecp256k1(t *testing.T) {
	v := vectors(t)
	c := caseWithAlgorithm(t, v, "secp256k1")
	valid, err := dstack.VerifySignature("k256", unhex(t, c.Data), unhex(t, c.Signature), unhex(t, c.PublicKey))
	if err != nil {
		t.Fatalf("k256 alias: %v", err)
	}
	if !valid {
		t.Error("k256 alias did not verify a valid secp256k1 signature")
	}
}

func TestVerifySignatureMalformedInputsErrorRatherThanReportFalse(t *testing.T) {
	if _, err := dstack.VerifySignature("rsa", []byte("x"), make([]byte, 64), make([]byte, 32)); err == nil {
		t.Error("expected an error for an unknown algorithm")
	}
	if _, err := dstack.VerifySignature("ed25519", []byte("x"), make([]byte, 64), make([]byte, 31)); err == nil {
		t.Error("expected an error for a 31-byte ed25519 public key")
	}
	if _, err := dstack.VerifySignature("ed25519", []byte("x"), make([]byte, 63), make([]byte, 32)); err == nil {
		t.Error("expected an error for a 63-byte ed25519 signature")
	}

	v := vectors(t)
	c := caseWithAlgorithm(t, v, "secp256k1_prehashed")
	// A prehashed digest must be exactly 32 bytes.
	if _, err := dstack.VerifySignature(
		"secp256k1_prehashed", []byte("short"), unhex(t, c.Signature), unhex(t, c.PublicKey)); err == nil {
		t.Error("expected an error for a prehashed digest that is not 32 bytes")
	}
	// A secp256k1 signature must be raw 64-byte r||s, not DER.
	if _, err := dstack.VerifySignature(
		"secp256k1", []byte("x"), make([]byte, 70), unhex(t, c.PublicKey)); err == nil {
		t.Error("expected an error for a 70-byte secp256k1 signature")
	}
	// The public key must be SEC1.
	if _, err := dstack.VerifySignature(
		"secp256k1", []byte("x"), unhex(t, c.Signature), make([]byte, 33)); err == nil {
		t.Error("expected an error for a malformed secp256k1 public key")
	}
}

func TestVerifySignatureAcceptsUncompressedSecp256k1Keys(t *testing.T) {
	v := vectors(t)
	c := caseWithAlgorithm(t, v, "secp256k1")
	compressed := unhex(t, c.PublicKey)
	if len(compressed) != 33 {
		t.Fatalf("expected a 33-byte compressed key in the vectors, got %d", len(compressed))
	}
	parsed, err := secp256k1.ParsePubKey(compressed)
	if err != nil {
		t.Fatalf("parse compressed key: %v", err)
	}
	uncompressed := parsed.SerializeUncompressed()
	valid, err := dstack.VerifySignature(c.Algorithm, unhex(t, c.Data), unhex(t, c.Signature), uncompressed)
	if err != nil {
		t.Fatalf("uncompressed key: %v", err)
	}
	if !valid {
		t.Error("a valid signature was rejected under the uncompressed SEC1 key")
	}
}

func TestVerifySignatureChainVerifiesToTheKMSRoot(t *testing.T) {
	v := vectors(t)
	appID := unhex(t, v.AppID)
	kmsRoot := unhex(t, v.KMSRootPubKey)
	expectedAppRoot := unhex(t, v.AppRootPubKey)

	for _, c := range v.Cases {
		appRoot, err := dstack.VerifySignatureChain(dstack.SignatureChainInput{
			Algorithm:      c.Algorithm,
			Data:           unhex(t, c.Data),
			PublicKey:      unhex(t, c.PublicKey),
			SignatureChain: chainOf(t, c),
			AppID:          appID,
			KMSRootPubKey:  kmsRoot,
		})
		if err != nil {
			t.Fatalf("%s: %v", c.Algorithm, err)
		}
		if !bytes.Equal(appRoot, expectedAppRoot) {
			t.Errorf("%s: recovered the wrong app root key: got %x, want %x",
				c.Algorithm, appRoot, expectedAppRoot)
		}
	}
}

func TestVerifySignatureChainExplicitPurposeMatchesTheDefault(t *testing.T) {
	v := vectors(t)
	c := v.Cases[0]
	appRoot, err := dstack.VerifySignatureChain(dstack.SignatureChainInput{
		Algorithm:      c.Algorithm,
		Data:           unhex(t, c.Data),
		PublicKey:      unhex(t, c.PublicKey),
		SignatureChain: chainOf(t, c),
		AppID:          unhex(t, v.AppID),
		KMSRootPubKey:  unhex(t, v.KMSRootPubKey),
		Purpose:        v.Purpose,
	})
	if err != nil {
		t.Fatalf("explicit purpose %q: %v", v.Purpose, err)
	}
	if !bytes.Equal(appRoot, unhex(t, v.AppRootPubKey)) {
		t.Error("explicit purpose recovered a different app root key than the default")
	}

	// A different purpose recovers some other key, which the KMS never signed.
	if _, err := dstack.VerifySignatureChain(dstack.SignatureChainInput{
		Algorithm:      c.Algorithm,
		Data:           unhex(t, c.Data),
		PublicKey:      unhex(t, c.PublicKey),
		SignatureChain: chainOf(t, c),
		AppID:          unhex(t, v.AppID),
		KMSRootPubKey:  unhex(t, v.KMSRootPubKey),
		Purpose:        "encryption",
	}); err == nil {
		t.Error("expected a chain bound to a different purpose to be rejected")
	}
}

func TestVerifySignatureChainAnchoredAtAForeignKMSRootIsRejected(t *testing.T) {
	v := vectors(t)
	c := v.Cases[0]
	_, err := dstack.VerifySignatureChain(dstack.SignatureChainInput{
		Algorithm:      c.Algorithm,
		Data:           unhex(t, c.Data),
		PublicKey:      unhex(t, c.PublicKey),
		SignatureChain: chainOf(t, c),
		AppID:          unhex(t, v.AppID),
		KMSRootPubKey:  unhex(t, v.WrongKMSRootPubKey),
	})
	if err == nil {
		t.Fatal("a chain not anchored at our KMS root must be rejected")
	}
	if !strings.Contains(err.Error(), "not anchored") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifySignatureChainForADifferentAppIDIsRejected(t *testing.T) {
	v := vectors(t)
	c := v.Cases[0]
	appID := unhex(t, v.AppID)
	appID[0] ^= 0xff

	if _, err := dstack.VerifySignatureChain(dstack.SignatureChainInput{
		Algorithm:      c.Algorithm,
		Data:           unhex(t, c.Data),
		PublicKey:      unhex(t, c.PublicKey),
		SignatureChain: chainOf(t, c),
		AppID:          appID,
		KMSRootPubKey:  unhex(t, v.KMSRootPubKey),
	}); err == nil {
		t.Fatal("a chain issued for a different app_id must be rejected")
	}
}

func TestVerifySignatureChainTamperedPayloadBreaksTheChain(t *testing.T) {
	v := vectors(t)
	c := v.Cases[0]
	if _, err := dstack.VerifySignatureChain(dstack.SignatureChainInput{
		Algorithm:      c.Algorithm,
		Data:           []byte("a different payload entirely"),
		PublicKey:      unhex(t, c.PublicKey),
		SignatureChain: chainOf(t, c),
		AppID:          unhex(t, v.AppID),
		KMSRootPubKey:  unhex(t, v.KMSRootPubKey),
	}); err == nil {
		t.Fatal("a chain over a tampered payload must be rejected")
	}
}

func TestVerifySignatureChainMalformedInputs(t *testing.T) {
	v := vectors(t)
	c := v.Cases[0]
	chain := chainOf(t, c)

	if _, err := dstack.VerifySignatureChain(dstack.SignatureChainInput{
		Algorithm:      c.Algorithm,
		Data:           unhex(t, c.Data),
		PublicKey:      unhex(t, c.PublicKey),
		SignatureChain: chain[:2],
		AppID:          unhex(t, v.AppID),
		KMSRootPubKey:  unhex(t, v.KMSRootPubKey),
	}); err == nil {
		t.Error("expected an error for a chain with fewer than 3 elements")
	}

	if _, err := dstack.VerifySignatureChain(dstack.SignatureChainInput{
		Algorithm:      c.Algorithm,
		Data:           unhex(t, c.Data),
		PublicKey:      unhex(t, c.PublicKey),
		SignatureChain: chain,
		AppID:          make([]byte, 19),
		KMSRootPubKey:  unhex(t, v.KMSRootPubKey),
	}); err == nil {
		t.Error("expected an error for an app_id that is not 20 bytes")
	}

	if _, err := dstack.VerifySignatureChain(dstack.SignatureChainInput{
		Algorithm:      c.Algorithm,
		Data:           unhex(t, c.Data),
		PublicKey:      unhex(t, c.PublicKey),
		SignatureChain: chain,
		AppID:          unhex(t, v.AppID),
		KMSRootPubKey:  make([]byte, 33),
	}); err == nil {
		t.Error("expected an error for a malformed KMS root public key")
	}

	// A recoverable link must be 65 bytes.
	shortLink := [][]byte{chain[0], chain[1][:64], chain[2]}
	if _, err := dstack.VerifySignatureChain(dstack.SignatureChainInput{
		Algorithm:      c.Algorithm,
		Data:           unhex(t, c.Data),
		PublicKey:      unhex(t, c.PublicKey),
		SignatureChain: shortLink,
		AppID:          unhex(t, v.AppID),
		KMSRootPubKey:  unhex(t, v.KMSRootPubKey),
	}); err == nil {
		t.Error("expected an error for a 64-byte recoverable signature")
	}
}

func TestVerifySignPurposeIsTheAgentSideConstant(t *testing.T) {
	if dstack.SignPurpose != "signing" {
		t.Errorf("SignPurpose = %q, want \"signing\"", dstack.SignPurpose)
	}
	if dstack.SignPath != "vms" {
		t.Errorf("SignPath = %q, want \"vms\"", dstack.SignPath)
	}
	v := vectors(t)
	if v.Purpose != dstack.SignPurpose || v.Path != dstack.SignPath {
		t.Errorf("vectors disagree about the agent-side constants: purpose=%q path=%q", v.Purpose, v.Path)
	}
}
