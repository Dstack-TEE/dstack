// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// Every field the guest's AppCompose can carry, with a non-default value.
//
// A closed struct drops what it does not know, and what this package computes
// is a compose hash that gets whitelisted on chain -- so a dropped field means
// the digest describes an app-compose that is not the one being deployed, and
// nothing anywhere notices. `port_policy`, `init_script`, `storage_fs`,
// `swap_size`, `event_log_version`, `verity_volumes` and
// `requirements.gpu_policy` were all in that state.
const fullAppCompose = `{
  "manifest_version": "3",
  "name": "demo",
  "features": ["x"],
  "runner": "docker-compose",
  "snapshotter": "overlayfs",
  "docker_compose_file": "services: {}\n",
  "init_script": ["a.sh", "b.sh"],
  "public_logs": true,
  "public_sysinfo": true,
  "public_tcbinfo": true,
  "kms_enabled": true,
  "gateway_enabled": true,
  "local_key_provider_enabled": true,
  "key_provider": "kms",
  "key_provider_id": "aabb",
  "allowed_envs": ["FOO"],
  "no_instance_id": true,
  "secure_time": true,
  "storage_fs": "ext4",
  "swap_size": "2G",
  "event_log_version": 2,
  "port_policy": {"ports": [{"port": 8080, "pp": true}], "restrict_mode": true},
  "verity_volumes": [{"source": "v.img", "verity_root": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "target": "/mnt/v"}],
  "requirements": {
    "os_version": ">=0.6.1",
    "platforms": ["dstack-tdx"],
    "tdx_measure_acpi_tables": true,
    "launch_token_hash": "ff00",
    "gpu_policy": {"attest_gpu": true, "rego": "package policy", "allow_devtools": true}
  }
}`

func hashOfRawJSON(t *testing.T, raw string) string {
	t.Helper()
	var generic interface{}
	if err := json.Unmarshal([]byte(raw), &generic); err != nil {
		t.Fatal(err)
	}
	canonical, err := toDeterministicJSON(generic)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// Nothing present in an app-compose may be lost by passing through this SDK.
func TestEveryFieldSurvivesTheRoundTrip(t *testing.T) {
	var compose AppCompose
	if err := json.Unmarshal([]byte(fullAppCompose), &compose); err != nil {
		t.Fatal(err)
	}
	got, err := GetComposeHash(compose)
	if err != nil {
		t.Fatal(err)
	}
	if want := hashOfRawJSON(t, fullAppCompose); got != want {
		reencoded, _ := json.MarshalIndent(compose, "", "  ")
		t.Fatalf("a field was dropped or changed.\n got=%s\nwant=%s\nre-encoded:\n%s", got, want, reencoded)
	}
}

// A guest that gains a field before this SDK does must still hash correctly,
// which is what `Extra` is for.
func TestAnUnknownFieldStillReachesTheHash(t *testing.T) {
	withUnknown := `{"runner":"docker-compose","some_future_field":{"a":1},"requirements":{"another_future_one":true}}`
	var compose AppCompose
	if err := json.Unmarshal([]byte(withUnknown), &compose); err != nil {
		t.Fatal(err)
	}
	got, err := GetComposeHash(compose)
	if err != nil {
		t.Fatal(err)
	}
	if want := hashOfRawJSON(t, withUnknown); got != want {
		reencoded, _ := json.Marshal(compose)
		t.Fatalf("an unknown field was dropped.\n got=%s\nwant=%s\nre-encoded: %s", got, want, reencoded)
	}
}

// A typed field and an Extra key of the same name must not both be emitted.
func TestADeclaredFieldWinsOverExtra(t *testing.T) {
	compose := AppCompose{
		Runner: "docker-compose",
		Extra:  map[string]interface{}{"runner": "bash"},
	}
	encoded, err := json.Marshal(compose)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["runner"] != "docker-compose" {
		t.Fatalf("the declared field should win, got %v", decoded["runner"])
	}
}
