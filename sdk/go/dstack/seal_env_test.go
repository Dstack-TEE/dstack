// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
	"github.com/cloudflare/circl/hpke"
)

func TestSealEnvRoundTripAndBinding(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
	publicKey, privateKey, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	key, err := publicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		envs     []dstack.EnvVar
		epoch    uint32
		appEpoch uint32
		prefix   string
		want     string
	}{
		{"unicode", []dstack.EnvVar{{Key: "MESSAGE", Value: "Hello 世界"}}, 42, 0, "", `{"env":[{"key":"MESSAGE","value":"Hello 世界"}]}`},
		{"app_epoch", nil, 42, 2, "", `{"env":[]}`},
		{"empty", []dstack.EnvVar{}, 0, 0, "0x", `{"env":[]}`},
		{"nil_max_epoch", nil, ^uint32(0), 0, "", `{"env":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sealed, err := dstack.SealEnvAtEpochs(tc.envs, tc.prefix+hex.EncodeToString(key), tc.epoch, tc.appEpoch)
			if err != nil {
				t.Fatal(err)
			}
			var envelope struct {
				Version    uint32 `json:"version"`
				RootEpoch  uint32 `json:"root_epoch"`
				AppEpoch   uint32 `json:"app_epoch"`
				Enc        []byte `json:"enc"`
				Ciphertext []byte `json:"ciphertext"`
			}
			if err := json.Unmarshal([]byte(sealed), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Version != 1 || envelope.AppEpoch != tc.appEpoch || envelope.RootEpoch != tc.epoch || len(envelope.Enc) != 32 {
				t.Fatal("invalid sealed env envelope")
			}
			open := func(enc, ciphertext []byte, epoch uint32, aad []byte) ([]byte, error) {
				info := fmt.Sprintf("dstack-sealed-env-v1:%d:%d", epoch, tc.appEpoch)
				receiver, err := suite.NewReceiver(privateKey, []byte(info))
				if err != nil {
					return nil, err
				}
				opener, err := receiver.Setup(enc)
				if err != nil {
					return nil, err
				}
				return opener.Open(ciphertext, aad)
			}
			plaintext, err := open(envelope.Enc, envelope.Ciphertext, tc.epoch, nil)
			if err != nil {
				t.Fatal(err)
			}
			if string(plaintext) != tc.want {
				t.Fatalf("unexpected plaintext: %s", plaintext)
			}
			t.Run("epoch_bound", func(t *testing.T) {
				if _, err := open(envelope.Enc, envelope.Ciphertext, tc.epoch^1, nil); err == nil {
					t.Fatal("accepted wrong epoch")
				}
			})
			t.Run("aad_bound", func(t *testing.T) {
				if _, err := open(envelope.Enc, envelope.Ciphertext, tc.epoch, []byte("unexpected")); err == nil {
					t.Fatal("accepted nonempty AAD")
				}
			})
			t.Run("ciphertext_tamper", func(t *testing.T) {
				ct := append([]byte(nil), envelope.Ciphertext...)
				ct[len(ct)-1] ^= 1
				if _, err := open(envelope.Enc, ct, tc.epoch, nil); err == nil {
					t.Fatal("accepted tampered ciphertext")
				}
			})
			t.Run("enc_tamper", func(t *testing.T) {
				enc := append([]byte(nil), envelope.Enc...)
				enc[0] ^= 1
				if _, err := open(enc, envelope.Ciphertext, tc.epoch, nil); err == nil {
					t.Fatal("accepted tampered encapsulation")
				}
			})
		})
	}
}

func TestSealEnvInvalidKey(t *testing.T) {
	for name, key := range map[string]string{
		"empty": "", "non_hex": "zz", "odd_hex": "abc",
		"short": strings.Repeat("11", 31), "long": strings.Repeat("11", 33),
		"zero": strings.Repeat("00", 32), "low_order": "01" + strings.Repeat("00", 31),
	} {
		t.Run(name, func(t *testing.T) {
			sealed, err := dstack.SealEnv(nil, key, 0)
			if err == nil || sealed != "" {
				t.Fatal("expected invalid key error and no envelope")
			}
		})
	}
}
