// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// EthereumAccount represents an Ethereum account with address and private key
type EthereumAccount struct {
	Address    common.Address
	PrivateKey *ecdsa.PrivateKey
}

// ToEthereumAccount creates an Ethereum account from GetKeyResponse or GetTlsKeyResponse (legacy method).
// Deprecated: Use ToEthereumAccountSecure instead. This method has security concerns.
func ToEthereumAccount(keyResponse interface{}) (*EthereumAccount, error) {
	switch resp := keyResponse.(type) {
	case *GetTlsKeyResponse:
		// Legacy behavior for GetTlsKeyResponse with warning
		fmt.Println("Warning: toEthereumAccount: Please don't use GetTlsKey method to get key, use GetKey instead.")
		
		keyBytes, err := resp.AsUint8Array(32)
		if err != nil {
			return nil, fmt.Errorf("failed to extract key bytes: %w", err)
		}
		
		privateKey, err := crypto.ToECDSA(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to create ECDSA private key: %w", err)
		}
		
		address := crypto.PubkeyToAddress(privateKey.PublicKey)
		
		return &EthereumAccount{
			Address:    address,
			PrivateKey: privateKey,
		}, nil
		
	case *GetKeyResponse:
		keyBytes, err := resp.DecodeKey()
		if err != nil {
			return nil, fmt.Errorf("failed to decode key: %w", err)
		}
		
		privateKey, err := crypto.ToECDSA(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to create ECDSA private key: %w", err)
		}
		
		address := crypto.PubkeyToAddress(privateKey.PublicKey)
		
		return &EthereumAccount{
			Address:    address,
			PrivateKey: privateKey,
		}, nil
		
	default:
		return nil, fmt.Errorf("unsupported key response type")
	}
}

// ToEthereumAccountSecure creates an Ethereum account from GetKeyResponse or GetTlsKeyResponse using secure key derivation.
// This method applies SHA256 hashing to the complete key material for enhanced security.
func ToEthereumAccountSecure(keyResponse interface{}) (*EthereumAccount, error) {
	switch resp := keyResponse.(type) {
	case *GetTlsKeyResponse:
		// Legacy behavior for GetTlsKeyResponse with warning
		fmt.Println("Warning: toEthereumAccountSecure: Please don't use GetTlsKey method to get key, use GetKey instead.")
		
		keyBytes, err := resp.AsUint8Array()
		if err != nil {
			return nil, fmt.Errorf("failed to extract key bytes: %w", err)
		}
		
		// Apply SHA256 hashing for security
		hash := sha256.Sum256(keyBytes)
		
		privateKey, err := crypto.ToECDSA(hash[:])
		if err != nil {
			return nil, fmt.Errorf("failed to create ECDSA private key: %w", err)
		}
		
		address := crypto.PubkeyToAddress(privateKey.PublicKey)
		
		return &EthereumAccount{
			Address:    address,
			PrivateKey: privateKey,
		}, nil
		
	case *GetKeyResponse:
		keyBytes, err := resp.DecodeKey()
		if err != nil {
			return nil, fmt.Errorf("failed to decode key: %w", err)
		}
		
		privateKey, err := crypto.ToECDSA(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to create ECDSA private key: %w", err)
		}
		
		address := crypto.PubkeyToAddress(privateKey.PublicKey)
		
		return &EthereumAccount{
			Address:    address,
			PrivateKey: privateKey,
		}, nil
		
	default:
		return nil, fmt.Errorf("unsupported key response type")
	}
}

// Sign signs a message hash using the account's private key
func (a *EthereumAccount) Sign(messageHash []byte) ([]byte, error) {
	return crypto.Sign(messageHash, a.PrivateKey)
}

// PublicKey returns the public key
func (a *EthereumAccount) PublicKey() *ecdsa.PublicKey {
	return &a.PrivateKey.PublicKey
}