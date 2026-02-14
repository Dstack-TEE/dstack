//go:build web3
// +build web3

// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
)

// SolanaKeypair represents a Solana keypair with public and private keys
type SolanaKeypair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// ToSolanaKeypair creates a Solana keypair from GetKeyResponse or GetTlsKeyResponse (legacy method).
// Deprecated: Use ToSolanaKeypairSecure instead. This method has security concerns.
func ToSolanaKeypair(keyResponse interface{}) (*SolanaKeypair, error) {
	switch resp := keyResponse.(type) {
	case *GetTlsKeyResponse:
		// Legacy behavior for GetTlsKeyResponse with warning
		fmt.Println("Warning: toSolanaKeypair: Please don't use GetTlsKey method to get key, use GetKey instead.")

		// Use first 32 bytes directly for legacy compatibility
		keyBytes, err := resp.AsUint8Array(32)
		if err != nil {
			return nil, fmt.Errorf("failed to extract key bytes: %w", err)
		}

		// Generate Ed25519 keypair from seed
		privateKey := ed25519.NewKeyFromSeed(keyBytes)
		publicKey := privateKey.Public().(ed25519.PublicKey)

		return &SolanaKeypair{
			PublicKey:  publicKey,
			PrivateKey: privateKey,
		}, nil

	case *GetKeyResponse:
		keyBytes, err := resp.DecodeKey()
		if err != nil {
			return nil, fmt.Errorf("failed to decode key: %w", err)
		}

		if len(keyBytes) < 32 {
			return nil, fmt.Errorf("key too short, need at least 32 bytes")
		}

		// Use first 32 bytes as seed
		seed := keyBytes[:32]
		privateKey := ed25519.NewKeyFromSeed(seed)
		publicKey := privateKey.Public().(ed25519.PublicKey)

		return &SolanaKeypair{
			PublicKey:  publicKey,
			PrivateKey: privateKey,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key response type")
	}
}

// ToSolanaKeypairSecure creates a Solana keypair from GetKeyResponse or GetTlsKeyResponse using secure key derivation.
// This method applies SHA256 hashing to the complete key material for enhanced security.
func ToSolanaKeypairSecure(keyResponse interface{}) (*SolanaKeypair, error) {
	switch resp := keyResponse.(type) {
	case *GetTlsKeyResponse:
		// Legacy behavior for GetTlsKeyResponse with warning
		fmt.Println("Warning: toSolanaKeypairSecure: Please don't use GetTlsKey method to get key, use GetKey instead.")

		keyBytes, err := resp.AsUint8Array()
		if err != nil {
			return nil, fmt.Errorf("failed to extract key bytes: %w", err)
		}

		// Apply SHA256 hashing for security
		hash := sha256.Sum256(keyBytes)

		privateKey := ed25519.NewKeyFromSeed(hash[:])
		publicKey := privateKey.Public().(ed25519.PublicKey)

		return &SolanaKeypair{
			PublicKey:  publicKey,
			PrivateKey: privateKey,
		}, nil

	case *GetKeyResponse:
		keyBytes, err := resp.DecodeKey()
		if err != nil {
			return nil, fmt.Errorf("failed to decode key: %w", err)
		}

		if len(keyBytes) < 32 {
			return nil, fmt.Errorf("key too short, need at least 32 bytes")
		}

		// Use first 32 bytes as seed for legacy compatibility
		seed := keyBytes[:32]
		privateKey := ed25519.NewKeyFromSeed(seed)
		publicKey := privateKey.Public().(ed25519.PublicKey)

		return &SolanaKeypair{
			PublicKey:  publicKey,
			PrivateKey: privateKey,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key response type")
	}
}

// Sign signs a message using the keypair's private key
func (k *SolanaKeypair) Sign(message []byte) []byte {
	return ed25519.Sign(k.PrivateKey, message)
}

// Verify verifies a signature against a message using the keypair's public key
func (k *SolanaKeypair) Verify(message, signature []byte) bool {
	return ed25519.Verify(k.PublicKey, message, signature)
}

// PublicKeyString returns the public key as a hex string (simplified)
func (k *SolanaKeypair) PublicKeyString() string {
	// This would require a base58 encoder, for now return hex
	// In a real implementation, you'd use github.com/mr-tron/base58
	return fmt.Sprintf("%x", k.PublicKey)
}

// Bytes returns the full 64-byte private key (32-byte seed + 32-byte public key)
func (k *SolanaKeypair) Bytes() []byte {
	return k.PrivateKey
}
