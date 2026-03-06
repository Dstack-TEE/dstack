// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// EnvVar represents an environment variable key-value pair.
type EnvVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// EncryptEnvVars encrypts environment variables using X25519 ECDH + AES-256-GCM.
//
// publicKeyHex is the remote X25519 public key (hex-encoded, with or without 0x prefix).
// Returns hex(ephemeral_pubkey || iv || ciphertext).
func EncryptEnvVars(envs []EnvVar, publicKeyHex string) (string, error) {
	cleanHex := strings.TrimPrefix(publicKeyHex, "0x")
	remotePubKey, err := hex.DecodeString(cleanHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}
	if len(remotePubKey) != 32 {
		return "", fmt.Errorf("invalid public key length: expected 32 bytes, got %d", len(remotePubKey))
	}

	envJSON, err := json.Marshal(struct {
		Env []EnvVar `json:"env"`
	}{Env: envs})
	if err != nil {
		return "", fmt.Errorf("failed to marshal env vars: %w", err)
	}

	ephemeralPrivKey := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivKey); err != nil {
		return "", fmt.Errorf("failed to generate ephemeral private key: %w", err)
	}

	ephemeralPubKey, err := curve25519.X25519(ephemeralPrivKey, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("failed to derive ephemeral public key: %w", err)
	}

	sharedSecret, err := curve25519.X25519(ephemeralPrivKey, remotePubKey)
	if err != nil {
		return "", fmt.Errorf("failed to derive shared secret: %w", err)
	}

	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return "", fmt.Errorf("failed to create aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create aes-gcm: %w", err)
	}

	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("failed to generate iv: %w", err)
	}

	ciphertext := gcm.Seal(nil, iv, envJSON, nil)
	result := make([]byte, 0, len(ephemeralPubKey)+len(iv)+len(ciphertext))
	result = append(result, ephemeralPubKey...)
	result = append(result, iv...)
	result = append(result, ciphertext...)

	return hex.EncodeToString(result), nil
}
