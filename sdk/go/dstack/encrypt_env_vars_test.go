// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
	"golang.org/x/crypto/curve25519"
)

func TestEncryptEnvVars(t *testing.T) {
	remotePriv := make([]byte, 32)
	if _, err := rand.Read(remotePriv); err != nil {
		t.Fatal(err)
	}
	remotePub, err := curve25519.X25519(remotePriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}

	envs := []dstack.EnvVar{
		{Key: "NODE_ENV", Value: "production"},
		{Key: "MESSAGE", Value: "Hello 世界"},
	}

	encryptedHex, err := dstack.EncryptEnvVars(envs, hex.EncodeToString(remotePub))
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := hex.DecodeString(encryptedHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(encrypted) <= 44 {
		t.Fatalf("expected encrypted payload > 44 bytes, got %d", len(encrypted))
	}

	ephemeralPub := encrypted[:32]
	iv := encrypted[32:44]
	ciphertext := encrypted[44:]

	sharedSecret, err := curve25519.X25519(remotePriv, ephemeralPub)
	if err != nil {
		t.Fatal(err)
	}

	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}

	var payload struct {
		Env []dstack.EnvVar `json:"env"`
	}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatal(err)
	}

	if len(payload.Env) != len(envs) {
		t.Fatalf("expected %d env vars, got %d", len(envs), len(payload.Env))
	}
	for i := range envs {
		if payload.Env[i] != envs[i] {
			t.Fatalf("env var mismatch at %d: expected %+v, got %+v", i, envs[i], payload.Env[i])
		}
	}
}

func TestEncryptEnvVarsInvalidKey(t *testing.T) {
	_, err := dstack.EncryptEnvVars([]dstack.EnvVar{{Key: "A", Value: "B"}}, "abcd")
	if err == nil {
		t.Fatal("expected error for invalid public key length")
	}
}
