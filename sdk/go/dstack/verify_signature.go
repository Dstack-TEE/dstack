// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack

import (
	"bytes"
	"encoding/hex"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

// VerifyEnvEncryptPublicKey verifies the signature of a public key.
//
// Parameters:
//   - publicKey: The public key bytes to verify (32 bytes)
//   - signature: The signature bytes (65 bytes)
//   - appID: The application ID
//
// Returns the compressed public key if valid, nil otherwise
func VerifyEnvEncryptPublicKey(publicKey []byte, signature []byte, appID string) ([]byte, error) {
	if len(signature) != 65 {
		return nil, nil
	}

	// Create the message to verify
	prefix := []byte("dstack-env-encrypt-pubkey")
	
	// Remove 0x prefix if present
	cleanAppID := appID
	if strings.HasPrefix(appID, "0x") {
		cleanAppID = appID[2:]
	}
	
	appIDBytes, err := hex.DecodeString(cleanAppID)
	if err != nil {
		return nil, nil
	}
	
	separator := []byte(":")
	
	// Construct message: prefix + ":" + app_id + public_key
	message := bytes.Join([][]byte{prefix, separator, appIDBytes, publicKey}, nil)
	
	// Hash the message with Keccak-256
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)
	
	// Extract r, s, v from signature (last byte is recovery id)
	r := signature[0:32]
	s := signature[32:64]
	recovery := signature[64]
	
	// Create signature in format expected by go-ethereum
	sigBytes := make([]byte, 64)
	copy(sigBytes[0:32], r)
	copy(sigBytes[32:64], s)
	
	// Recover the public key from the signature
	recoveredPubKey, err := crypto.SigToPub(messageHash, append(sigBytes, recovery))
	if err != nil {
		return nil, nil
	}
	
	// Return compressed public key
	compressedPubKey := crypto.CompressPubkey(recoveredPubKey)
	
	// Add 0x prefix
	result := make([]byte, len(compressedPubKey)+2)
	result[0] = '0'
	result[1] = 'x'
	copy(result[2:], []byte(hex.EncodeToString(compressedPubKey)))
	
	return result, nil
}

// VerifySignatureSimple is a simplified version for basic signature verification
func VerifySignatureSimple(message []byte, signature []byte, expectedPubKey []byte) bool {
	if len(signature) != 65 {
		return false
	}
	
	// Hash the message
	hash := crypto.Keccak256Hash(message)
	
	// Remove recovery ID for verification
	sig := signature[:64]
	
	// Verify signature
	return crypto.VerifySignature(expectedPubKey, hash.Bytes(), sig)
}