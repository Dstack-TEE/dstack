// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

const (
	defaultVerifyMaxAgeSeconds     uint64 = 300
	defaultVerifyFutureSkewSeconds uint64 = 60
)

// VerifyEnvEncryptPublicKeyOptions configures timestamp validation for signature verification.
type VerifyEnvEncryptPublicKeyOptions struct {
	MaxAgeSeconds     uint64
	FutureSkewSeconds uint64
}

func normalizeVerifyOptions(opts *VerifyEnvEncryptPublicKeyOptions) (maxAgeSeconds uint64, futureSkewSeconds uint64) {
	maxAgeSeconds = defaultVerifyMaxAgeSeconds
	futureSkewSeconds = defaultVerifyFutureSkewSeconds
	if opts == nil {
		return
	}
	if opts.MaxAgeSeconds > 0 {
		maxAgeSeconds = opts.MaxAgeSeconds
	}
	if opts.FutureSkewSeconds > 0 {
		futureSkewSeconds = opts.FutureSkewSeconds
	}
	return
}

func buildVerifyMessage(publicKey []byte, appID string) ([]byte, error) {
	prefix := []byte("dstack-env-encrypt-pubkey")

	cleanAppID := appID
	if strings.HasPrefix(appID, "0x") {
		cleanAppID = appID[2:]
	}

	appIDBytes, err := hex.DecodeString(cleanAppID)
	if err != nil {
		return nil, err
	}

	separator := []byte(":")
	return bytes.Join([][]byte{prefix, separator, appIDBytes, publicKey}, nil), nil
}

func keccak256(data []byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func toCompactSignature(signature []byte) ([]byte, error) {
	if len(signature) != 65 {
		return nil, nil
	}

	recovery := signature[64]
	if recovery >= 27 {
		recovery -= 27
	}
	if recovery > 3 {
		return nil, nil
	}

	compact := make([]byte, 65)
	compact[0] = 27 + recovery + 4 // compressed key
	copy(compact[1:33], signature[:32])
	copy(compact[33:65], signature[32:64])
	return compact, nil
}

func recoverCompressedPublicKey(message []byte, signature []byte) ([]byte, error) {
	if len(signature) != 65 {
		return nil, nil
	}

	compactSig, err := toCompactSignature(signature)
	if err != nil || compactSig == nil {
		return nil, err
	}

	messageHash := keccak256(message)
	pubKey, _, err := secp256k1ecdsa.RecoverCompact(compactSig, messageHash)
	if err != nil {
		return nil, nil
	}

	compressed := pubKey.SerializeCompressed()
	result := make([]byte, 2+hex.EncodedLen(len(compressed)))
	result[0] = '0'
	result[1] = 'x'
	hex.Encode(result[2:], compressed)
	return result, nil
}

// VerifyEnvEncryptPublicKey verifies the signature of a public key (legacy format without timestamp).
func VerifyEnvEncryptPublicKey(publicKey []byte, signature []byte, appID string) ([]byte, error) {
	message, err := buildVerifyMessage(publicKey, appID)
	if err != nil {
		return nil, nil
	}
	return recoverCompressedPublicKey(message, signature)
}

// VerifyEnvEncryptPublicKeyWithTimestamp verifies a public-key signature with timestamp freshness checks.
//
// Message format:
//
//	prefix + ":" + app_id + timestamp_be_u64 + public_key
func VerifyEnvEncryptPublicKeyWithTimestamp(
	publicKey []byte,
	signature []byte,
	appID string,
	timestamp uint64,
	opts *VerifyEnvEncryptPublicKeyOptions,
) ([]byte, error) {
	if len(signature) != 65 {
		return nil, nil
	}

	maxAgeSeconds, futureSkewSeconds := normalizeVerifyOptions(opts)
	now := uint64(time.Now().Unix())
	if timestamp > now {
		if timestamp-now > futureSkewSeconds {
			return nil, fmt.Errorf("timestamp is too far in the future")
		}
	} else if now-timestamp > maxAgeSeconds {
		return nil, fmt.Errorf("timestamp is too old: %ds > %ds", now-timestamp, maxAgeSeconds)
	}

	baseMessage, err := buildVerifyMessage(publicKey, appID)
	if err != nil {
		return nil, nil
	}

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, timestamp)
	message := append(append([]byte{}, baseMessage[:len(baseMessage)-len(publicKey)]...), timestampBytes...)
	message = append(message, publicKey...)

	return recoverCompressedPublicKey(message, signature)
}

// VerifySignatureSimple is a simplified version for basic signature verification.
func VerifySignatureSimple(message []byte, signature []byte, expectedPubKey []byte) bool {
	if len(signature) != 65 {
		return false
	}

	pubKey, err := secp256k1.ParsePubKey(expectedPubKey)
	if err != nil {
		return false
	}

	r := new(secp256k1.ModNScalar)
	s := new(secp256k1.ModNScalar)
	if r.SetByteSlice(signature[:32]) {
		return false
	}
	if s.SetByteSlice(signature[32:64]) {
		return false
	}

	sig := secp256k1ecdsa.NewSignature(r, s)
	return sig.Verify(keccak256(message), pubKey)
}
