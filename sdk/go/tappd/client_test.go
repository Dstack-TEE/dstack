// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package tappd_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Dstack-TEE/dstack/sdk/go/tappd"
)

func TestDeriveKey(t *testing.T) {
	client := tappd.NewTappdClient()
	resp, err := client.DeriveKeyWithSubjectAndAltNames(context.Background(), "/", "test", nil)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}

	if len(resp.CertificateChain) == 0 {
		t.Error("expected certificate chain to not be empty")
	}

	// Test ToBytes
	key, err := resp.ToBytes(-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) == 0 {
		t.Error("expected key bytes to not be empty")
	}

	// Test ToBytes with max length
	key, err = resp.ToBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Errorf("expected key length to be 32, got %d", len(key))
	}
}

func TestTdxQuote(t *testing.T) {
	client := tappd.NewTappdClient()
	resp, err := client.TdxQuote(context.Background(), []byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	if resp.Quote == "" {
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

	_, err = hex.DecodeString(resp.Quote)
	if err != nil {
		t.Errorf("expected quote to be a valid hex string: %v", err)
	}
}

func TestTdxQuoteRawHash(t *testing.T) {
	client := tappd.NewTappdClient()

	// Test valid raw hash
	resp, err := client.TdxQuoteWithHashAlgorithm(context.Background(), []byte("test"), tappd.RAW)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Quote == "" {
		t.Error("expected quote to not be empty")
	}

	// Test too large raw hash
	largeData := make([]byte, 65)
	_, err = client.TdxQuoteWithHashAlgorithm(context.Background(), largeData, tappd.RAW)
	if err == nil {
		t.Error("expected error for large raw hash data")
	}
	if !strings.Contains(err.Error(), "report data is too large") {
		t.Errorf("unexpected error message: %v", err)
	}
}
