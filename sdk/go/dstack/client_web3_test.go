//go:build web3
// +build web3

// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestGetKeySignatureVerification(t *testing.T) {
	expectedAppPubkey, _ := hex.DecodeString("02818494263695e8839122dbd88e281d7380622999df4e60a14befa0f2d096fc7c")
	expectedKmsPubkey, _ := hex.DecodeString("0321529e458424ab1f710a3a57ec4dad2fb195ddca572f7469242ba6c7563085b6")

	client := dstack.NewDstackClient()
	path := "/test/path"
	purpose := "test-purpose"
	resp, err := client.GetKey(context.Background(), path, purpose, "secp256k1")
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}

	if len(resp.SignatureChain) != 2 {
		t.Fatalf("expected signature chain to have 2 elements, got %d", len(resp.SignatureChain))
	}

	appSignature, err := hex.DecodeString(resp.SignatureChain[0])
	if err != nil {
		t.Fatalf("failed to decode app signature: %v", err)
	}
	kmsSignature, err := hex.DecodeString(resp.SignatureChain[1])
	if err != nil {
		t.Fatalf("failed to decode KMS signature: %v", err)
	}

	infoResp, err := client.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	derivedPubKey, err := derivePublicKeyFromPrivate(resp.Key)
	if err != nil {
		t.Fatalf("failed to derive public key: %v", err)
	}

	message := fmt.Sprintf("%s:%s", purpose, hex.EncodeToString(derivedPubKey))
	appPubKey, err := recoverPublicKey(message, appSignature)
	if err != nil {
		t.Fatalf("failed to recover app public key: %v", err)
	}
	appPubKeyCompressed, err := compressPublicKey(appPubKey)
	if err != nil {
		t.Fatalf("failed to compress recovered public key: %v", err)
	}
	if !bytes.Equal(appPubKeyCompressed, expectedAppPubkey) {
		t.Errorf("app public key mismatch:\nExpected: %s\nActual:   %s", hex.EncodeToString(expectedAppPubkey), hex.EncodeToString(appPubKeyCompressed))
	}

	appIDFromInfo, err := hex.DecodeString(infoResp.AppID)
	if err != nil {
		t.Fatalf("failed to decode app ID: %v", err)
	}
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
		t.Errorf("KMS public key mismatch:\nExpected: %s\nActual:   %s", hex.EncodeToString(expectedKmsPubkey), hex.EncodeToString(kmsPubKeyCompressed))
	}

	verified, err := verifySignature(message, appSignature, appPubKey)
	if err != nil {
		t.Fatalf("signature verification error: %v", err)
	}
	if !verified {
		t.Error("app signature verification failed")
	}
}

func derivePublicKeyFromPrivate(privateKeyHex string) ([]byte, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to ECDSA private key: %w", err)
	}
	return crypto.CompressPubkey(&privateKey.PublicKey), nil
}

func recoverPublicKey(message string, signature []byte) ([]byte, error) {
	if len(signature) != 65 {
		return nil, fmt.Errorf("invalid signature length: expected 65 bytes, got %d", len(signature))
	}
	messageHash := crypto.Keccak256([]byte(message))
	pubKey, err := crypto.Ecrecover(messageHash, signature)
	if err != nil {
		return nil, fmt.Errorf("failed to recover public key: %w", err)
	}
	return pubKey, nil
}

func verifySignature(message string, signature []byte, publicKey []byte) (bool, error) {
	if len(signature) != 65 {
		return false, fmt.Errorf("invalid signature length: expected 65 bytes, got %d", len(signature))
	}
	messageHash := crypto.Keccak256([]byte(message))
	return crypto.VerifySignature(publicKey, messageHash, signature[:64]), nil
}

func compressPublicKey(uncompressedKey []byte) ([]byte, error) {
	if len(uncompressedKey) < 65 || uncompressedKey[0] != 4 {
		return nil, fmt.Errorf("invalid uncompressed public key")
	}
	x := new(big.Int).SetBytes(uncompressedKey[1:33])
	y := new(big.Int).SetBytes(uncompressedKey[33:65])
	pubKey := &ecdsa.PublicKey{Curve: crypto.S256(), X: x, Y: y}
	return crypto.CompressPubkey(pubKey), nil
}
