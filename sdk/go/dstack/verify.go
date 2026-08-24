// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// Local signature and signature-chain verification.
//
// Verification needs no key material and no attestation, so it does not belong
// behind an RPC to the guest agent: the agent's answer arrives over the socket
// unattested, which is no better than a caller checking the signature itself.
// The `Verify` RPC these functions replace was removed in v0.6.0.
//
// Two levels are available:
//
//   - VerifySignature checks one signature against a public key you already
//     have. It is the direct replacement for the old RPC and, on its own, proves
//     only that whoever holds that key signed the data.
//   - VerifySignatureChain walks the full chain from a SignResponse back to a
//     KMS root key **you supply**, which is what actually establishes that the
//     signer was a dstack app under that KMS.

package dstack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// kmsIssuedPrefix is the domain-separation prefix the KMS signs app root keys under.
const kmsIssuedPrefix = "dstack-kms-issued"

// Sign derives its key at this path with this purpose; both are fixed agent-side.
const (
	SignPath    = "vms"
	SignPurpose = "signing"
)

// normalizeAlgorithm maps `k256` onto `secp256k1`; they name the same thing and
// the agent normalized these too.
func normalizeAlgorithm(algorithm string) string {
	if algorithm == "k256" {
		return "secp256k1"
	}
	return algorithm
}

// parseK256Signature decodes a raw 64-byte `r ‖ s` signature.
func parseK256Signature(signature []byte) (*secp256k1ecdsa.Signature, error) {
	if len(signature) != 64 {
		return nil, fmt.Errorf("secp256k1 signature must be 64 bytes, but received %d", len(signature))
	}

	var r, s secp256k1.ModNScalar
	if overflow := r.SetByteSlice(signature[:32]); overflow {
		return nil, fmt.Errorf("invalid secp256k1 signature: r is not in the group order")
	}
	if overflow := s.SetByteSlice(signature[32:64]); overflow {
		return nil, fmt.Errorf("invalid secp256k1 signature: s is not in the group order")
	}
	if r.IsZero() || s.IsZero() {
		return nil, fmt.Errorf("invalid secp256k1 signature: r and s must both be non-zero")
	}
	// ECDSA is malleable: (r, n-s) verifies wherever (r, s) does. The Rust SDK's
	// k256 backend rejects the high-S form, so we must too -- otherwise a
	// signature stops being a unique identifier for a signed message, and this
	// SDK would disagree with every other dstack component about whether a given
	// blob is valid. The decred library accepts high-S, so the check is ours.
	if s.IsOverHalfOrder() {
		return nil, fmt.Errorf("non-canonical (high-S) secp256k1 signature")
	}
	return secp256k1ecdsa.NewSignature(&r, &s), nil
}

// VerifySignature verifies one signature against publicKey.
//
// algorithm is `ed25519`, `secp256k1` (alias `k256`), or `secp256k1_prehashed`,
// where data is already a 32-byte digest. Returns (false, nil) when the inputs
// are well-formed but the signature does not check out, and a non-nil error when
// they are not well-formed at all (bad key encoding, wrong signature length,
// unknown algorithm) -- a malformed input is a caller bug, not a verdict.
func VerifySignature(algorithm string, data []byte, signature []byte, publicKey []byte) (bool, error) {
	switch normalizeAlgorithm(algorithm) {
	case "ed25519":
		if len(publicKey) != ed25519.PublicKeySize {
			return false, fmt.Errorf("ed25519 public key must be %d bytes, but received %d",
				ed25519.PublicKeySize, len(publicKey))
		}
		if len(signature) != ed25519.SignatureSize {
			return false, fmt.Errorf("ed25519 signature must be %d bytes, but received %d",
				ed25519.SignatureSize, len(signature))
		}
		// Divergence from the Rust SDK, deliberate and harmless: ed25519_dalek
		// rejects a non-canonical or low-order point encoding as a malformed
		// key, where crypto/ed25519 offers no way to ask and simply reports
		// such a key as a failed verification. Both refuse the signature; only
		// the error-versus-verdict shape differs, and aligning it would mean
		// taking on an extra dependency just to decode the point.
		return ed25519.Verify(ed25519.PublicKey(publicKey), data, signature), nil

	case "secp256k1":
		pubKey, err := secp256k1.ParsePubKey(publicKey)
		if err != nil {
			return false, fmt.Errorf("invalid secp256k1 public key: %w", err)
		}
		sig, err := parseK256Signature(signature)
		if err != nil {
			return false, err
		}
		// The agent signs with SHA-256, so verification must hash the same way.
		digest := sha256.Sum256(data)
		return sig.Verify(digest[:], pubKey), nil

	case "secp256k1_prehashed":
		if len(data) != 32 {
			return false, fmt.Errorf(
				"pre-hashed verification requires a 32-byte digest, but received %d bytes", len(data))
		}
		pubKey, err := secp256k1.ParsePubKey(publicKey)
		if err != nil {
			return false, fmt.Errorf("invalid secp256k1 public key: %w", err)
		}
		sig, err := parseK256Signature(signature)
		if err != nil {
			return false, err
		}
		return sig.Verify(data, pubKey), nil

	default:
		return false, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// recoverCompressed recovers the compressed public key that produced a 65-byte
// `r ‖ s ‖ recid` signature over keccak256(message).
func recoverCompressed(message []byte, signature []byte) ([]byte, error) {
	if len(signature) != 65 {
		return nil, fmt.Errorf("recoverable signature must be 65 bytes, but received %d", len(signature))
	}
	// Applies the same canonicality rules as a plain signature, including high-S.
	if _, err := parseK256Signature(signature[:64]); err != nil {
		return nil, err
	}
	if signature[64] > 3 {
		return nil, fmt.Errorf("invalid recovery id %d", signature[64])
	}

	recovered, err := recoverCompressedPublicKey(message, signature)
	if err != nil {
		return nil, fmt.Errorf("failed to recover public key: %w", err)
	}
	if recovered == nil {
		return nil, fmt.Errorf("failed to recover public key")
	}
	// recoverCompressedPublicKey hands back `0x`-prefixed hex; the chain compares raw bytes.
	raw, err := hex.DecodeString(string(recovered[2:]))
	if err != nil {
		return nil, fmt.Errorf("failed to decode the recovered public key: %w", err)
	}
	return raw, nil
}

// SignatureChainInput carries the inputs to VerifySignatureChain.
//
// A struct rather than a positional argument list so that adding an input later
// does not break callers.
type SignatureChainInput struct {
	// Algorithm the payload was signed with.
	Algorithm string
	// Data is the signed payload; a 32-byte digest for `secp256k1_prehashed`.
	Data []byte
	// PublicKey is SignResponse.PublicKey -- the key that signed Data.
	PublicKey []byte
	// SignatureChain is SignResponse.SignatureChain, exactly 3 elements.
	SignatureChain [][]byte
	// AppID is the 20-byte app identity to hold the chain to.
	//
	// This must be the app id you *expect*, not merely whatever InfoResponse
	// echoed back -- that comes from the CVM being checked. Comparing a chain
	// against an app id the same CVM supplied proves only that it is
	// self-consistent.
	AppID []byte
	// KMSRootPubKey is the KMS root public key you already trust, compressed or
	// uncompressed SEC1.
	//
	// Get it from the DstackKms contract (`kmsInfo().k256Pubkey`) or pin it.
	// Reading it from the KMS you are verifying against proves nothing.
	KMSRootPubKey []byte
	// Purpose bound into the app-root link. Defaults to SignPurpose when empty,
	// which is what the Sign RPC always uses.
	Purpose string
}

// VerifySignatureChain verifies a Sign signature chain end to end and returns
// the app root public key (compressed SEC1, 33 bytes).
//
// Three links, all of which must hold:
//
//  1. SignatureChain[0] is a signature over Data by PublicKey.
//  2. SignatureChain[1] is the app root key attesting "{purpose}:{hex(PublicKey)}".
//  3. SignatureChain[2] is KMSRootPubKey attesting that app root key for AppID.
//
// Link 3 is the one that matters. Without comparing against a KMS root key you
// independently trust, a chain is just three signatures an attacker could have
// produced with their own keys.
func VerifySignatureChain(input SignatureChainInput) ([]byte, error) {
	if len(input.SignatureChain) != 3 {
		return nil, fmt.Errorf("signature chain must have 3 elements, but received %d",
			len(input.SignatureChain))
	}
	if len(input.AppID) != 20 {
		return nil, fmt.Errorf("app_id must be 20 bytes, but received %d", len(input.AppID))
	}

	purpose := input.Purpose
	if purpose == "" {
		purpose = SignPurpose
	}

	// Link 1: the payload signature. SignatureChain[0] *is* that signature; what
	// matters is that it checks out under PublicKey, which links 2 and 3 cover.
	valid, err := VerifySignature(input.Algorithm, input.Data, input.SignatureChain[0], input.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check the payload signature: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("payload signature is not valid for the given public key")
	}

	// Link 2: recover the app root key that vouched for the signing key.
	message := fmt.Sprintf("%s:%s", purpose, hex.EncodeToString(input.PublicKey))
	appRootPubKey, err := recoverCompressed([]byte(message), input.SignatureChain[1])
	if err != nil {
		return nil, fmt.Errorf("failed to recover the app root key: %w", err)
	}

	// Link 3: recover the KMS root key that vouched for the app root key, and
	// check it is the one we were told to trust.
	kmsMessage := make([]byte, 0, len(kmsIssuedPrefix)+1+len(input.AppID)+len(appRootPubKey))
	kmsMessage = append(kmsMessage, kmsIssuedPrefix...)
	kmsMessage = append(kmsMessage, ':')
	kmsMessage = append(kmsMessage, input.AppID...)
	kmsMessage = append(kmsMessage, appRootPubKey...)
	recoveredKMS, err := recoverCompressed(kmsMessage, input.SignatureChain[2])
	if err != nil {
		return nil, fmt.Errorf("failed to recover the KMS root key: %w", err)
	}

	// Normalize the expected key so callers may pass either SEC1 encoding.
	expectedKMS, err := secp256k1.ParsePubKey(input.KMSRootPubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid KMS root public key: %w", err)
	}
	if !bytes.Equal(recoveredKMS, expectedKMS.SerializeCompressed()) {
		return nil, fmt.Errorf("signature chain is not anchored at the expected KMS root key")
	}

	return appRootPubKey, nil
}
