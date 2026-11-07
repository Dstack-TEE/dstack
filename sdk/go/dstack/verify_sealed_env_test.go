// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

func TestVerifySealedEnvPublicKey(t *testing.T) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pin := []byte("0x" + hex.EncodeToString(privateKey.PubKey().SerializeCompressed()))
	pub := bytes.Repeat([]byte{0x22}, 32)
	app := bytes.Repeat([]byte{0x11}, 20)
	appID := hex.EncodeToString(app)
	epoch := uint32(0x01020304)
	now := uint64(time.Now().Unix())
	sign := func(prefix string, timestamp uint64) []byte {
		var message bytes.Buffer
		message.WriteString(prefix)
		message.Write(app)
		if err := binary.Write(&message, binary.BigEndian, epoch); err != nil {
			t.Fatal(err)
		}
		message.Write(pub)
		if err := binary.Write(&message, binary.BigEndian, timestamp); err != nil {
			t.Fatal(err)
		}
		hash := sha3.NewLegacyKeccak256()
		hash.Write(message.Bytes())
		compact := ecdsa.SignCompact(privateKey, hash.Sum(nil), true)
		return append(append([]byte(nil), compact[1:]...), compact[0]-31)
	}
	sig := sign("dstack-sealed-env-pubkey-v1:", now)
	for _, prefix := range []string{"", "0x", "0X"} {
		t.Run("valid_"+prefix, func(t *testing.T) {
			key, err := dstack.VerifySealedEnvPublicKey(pub, sig, prefix+appID, epoch, now, nil)
			if err != nil || !bytes.Equal(key, pin) {
				t.Fatalf("expected trusted signer, got %q, %v", key, err)
			}
		})
	}
	for _, tc := range []struct {
		name      string
		pub, sig  []byte
		app       string
		epoch     uint32
		timestamp uint64
	}{
		{"app", pub, sig, strings.Repeat("33", 20), epoch, now},
		{"epoch", pub, sig, appID, epoch + 1, now},
		{"public_key", bytes.Repeat([]byte{0x44}, 32), sig, appID, epoch, now},
		{"timestamp", pub, sig, appID, epoch, now - 1},
		{"domain", pub, sign("dstack-env-encrypt-pubkey:", now), appID, epoch, now},
	} {
		t.Run("context_"+tc.name, func(t *testing.T) {
			key, err := dstack.VerifySealedEnvPublicKey(tc.pub, tc.sig, tc.app, tc.epoch, tc.timestamp, nil)
			// Recovery can succeed for a different message; the trusted pin must not match.
			if err == nil && bytes.Equal(key, pin) {
				t.Fatal("changed context recovered trusted signer")
			}
		})
	}
	for _, tc := range []struct {
		name      string
		timestamp uint64
	}{
		{"old", now - 301}, {"future", now + 120}, {"zero", 0}, {"overflow", ^uint64(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := dstack.VerifySealedEnvPublicKey(pub, sign("dstack-sealed-env-pubkey-v1:", tc.timestamp), appID, epoch, tc.timestamp, nil)
			if err == nil || key != nil {
				t.Fatal("expected timestamp error")
			}
		})
	}
	for _, timestamp := range []uint64{now - 290, now + 60} {
		key, err := dstack.VerifySealedEnvPublicKey(pub, sign("dstack-sealed-env-pubkey-v1:", timestamp), appID, epoch, timestamp, nil)
		if err != nil || !bytes.Equal(key, pin) {
			t.Fatalf("timestamp within window rejected: %v", err)
		}
	}
}

func TestVerifySealedEnvPublicKeyInvalidInputs(t *testing.T) {
	pub := make([]byte, 32)
	sig := make([]byte, 65)
	app := strings.Repeat("11", 20)
	for _, tc := range []struct {
		name     string
		pub, sig []byte
		app      string
	}{
		{"short_key", pub[:31], sig, app}, {"long_key", make([]byte, 33), sig, app},
		{"short_signature", pub, sig[:64], app}, {"long_signature", pub, make([]byte, 66), app},
		{"invalid_signature", pub, sig, app},
		{"invalid_recovery", pub, append(make([]byte, 64), 255), app},
		{"empty_app", pub, sig, ""}, {"short_app", pub, sig, "11"},
		{"long_app", pub, sig, strings.Repeat("11", 21)}, {"nonhex_app", pub, sig, strings.Repeat("zz", 20)},
		{"odd_app", pub, sig, app + "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := dstack.VerifySealedEnvPublicKey(tc.pub, tc.sig, tc.app, 0, uint64(time.Now().Unix()), nil)
			if err == nil || key != nil {
				t.Fatal("expected invalid input error")
			}
		})
	}
}
