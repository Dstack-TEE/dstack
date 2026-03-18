// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack_test

import (
	"testing"
	"time"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
)

func TestVerifyEnvEncryptPublicKeyWithTimestampTooOld(t *testing.T) {
	pub := make([]byte, 32)
	sig := make([]byte, 65)
	now := uint64(time.Now().Unix())

	_, err := dstack.VerifyEnvEncryptPublicKeyWithTimestamp(
		pub,
		sig,
		"0000000000000000000000000000000000000000",
		now-301,
		nil,
	)
	if err == nil {
		t.Fatal("expected stale timestamp error")
	}
}

func TestVerifyEnvEncryptPublicKeyWithTimestampTooFuture(t *testing.T) {
	pub := make([]byte, 32)
	sig := make([]byte, 65)
	now := uint64(time.Now().Unix())

	_, err := dstack.VerifyEnvEncryptPublicKeyWithTimestamp(
		pub,
		sig,
		"0000000000000000000000000000000000000000",
		now+61,
		nil,
	)
	if err == nil {
		t.Fatal("expected future timestamp error")
	}
}

func TestVerifyEnvEncryptPublicKeyWithTimestampCustomMaxAge(t *testing.T) {
	pub := make([]byte, 32)
	sig := make([]byte, 65)
	now := uint64(time.Now().Unix())

	_, err := dstack.VerifyEnvEncryptPublicKeyWithTimestamp(
		pub,
		sig,
		"0000000000000000000000000000000000000000",
		now-400,
		&dstack.VerifyEnvEncryptPublicKeyOptions{MaxAgeSeconds: 500},
	)
	if err != nil {
		t.Fatalf("expected no timestamp error with custom max age, got: %v", err)
	}
}
