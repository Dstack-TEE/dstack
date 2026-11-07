// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cloudflare/circl/hpke"
)

// SealEnv encrypts environment variables into a version 1 sealed-env JSON envelope.
// It uses HPKE base mode with X25519, HKDF-SHA256 and AES-256-GCM, binding
// rootEpoch in the info string. publicKeyHex accepts an optional 0x prefix.
func SealEnv(envs []EnvVar, publicKeyHex string, rootEpoch uint32) (string, error) {
	return SealEnvAtEpochs(envs, publicKeyHex, rootEpoch, 0)
}

func SealEnvAtEpochs(envs []EnvVar, publicKeyHex string, rootEpoch, appEpoch uint32) (string, error) {
	key, err := hex.DecodeString(strings.TrimPrefix(publicKeyHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}
	if len(key) != 32 {
		return "", fmt.Errorf("invalid public key length: expected 32 bytes, got %d", len(key))
	}
	publicKey, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("invalid public key: %w", err)
	}
	if envs == nil {
		envs = []EnvVar{}
	}
	plaintext, err := json.Marshal(struct {
		Env []EnvVar `json:"env"`
	}{envs})
	if err != nil {
		return "", fmt.Errorf("failed to marshal env vars: %w", err)
	}
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
	info := fmt.Sprintf("dstack-sealed-env-v1:%d:%d", rootEpoch, appEpoch)
	sender, err := suite.NewSender(publicKey, []byte(info))
	if err != nil {
		return "", fmt.Errorf("failed to create HPKE sender: %w", err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to set up HPKE sender: %w", err)
	}
	ciphertext, err := sealer.Seal(plaintext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to seal env vars: %w", err)
	}
	envelope, err := json.Marshal(struct {
		Version    uint32 `json:"version"`
		RootEpoch  uint32 `json:"root_epoch"`
		AppEpoch   uint32 `json:"app_epoch"`
		Enc        []byte `json:"enc"`
		Ciphertext []byte `json:"ciphertext"`
	}{1, rootEpoch, appEpoch, enc, ciphertext})
	if err != nil {
		return "", fmt.Errorf("failed to marshal sealed env: %w", err)
	}
	return string(envelope), nil
}
