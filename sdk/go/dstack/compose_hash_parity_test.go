// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestZeroComposePointers(t *testing.T) {
	data, err := json.Marshal(AppCompose{InitScript: &InitScripts{}, SwapSize: &SwapSize{}})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["init_script"]) != "[]" || string(fields["swap_size"]) != "0" {
		t.Fatalf("unexpected zero pointer values: %s", data)
	}
}

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
    "platforms": ["dstack-tdx"],
    "tdx_measure_acpi_tables": true,
    "launch_token_hash": "ff00",
    "gpu_policy": {"attest_gpu": true, "rego": "package policy", "allow_devtools": true}
  }
}`

func TestComposeHashFixture(t *testing.T) {
	data, err := os.ReadFile("../../tests/compose-hash-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name       string          `json:"name"`
			AppCompose json.RawMessage `json:"app_compose"`
			SHA256     string          `json:"sha256"`
			Normalize  bool            `json:"normalize"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			var compose AppCompose
			if err := json.Unmarshal(tc.AppCompose, &compose); err != nil {
				t.Fatal(err)
			}
			got, err := GetComposeHash(compose, tc.Normalize)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.SHA256 {
				t.Fatalf("got %s want %s", got, tc.SHA256)
			}
		})
	}
}

func TestComposePresenceAndNestedExtras(t *testing.T) {
	for _, raw := range []string{`{"name":"x"}`, `{"runner":"bash","port_policy":{"ports":[{}]},"verity_volumes":[{}]}`, `{"runner":null}`, `{"runner":"docker-compose","key_provider_id":"","allowed_envs":[],"public_logs":false,"requirements":null}`, `{"runner":"docker-compose","requirements":{"health_check":false,"ephemeral_data_disk":false,"launch_token_hash":""},"docker_config":{"registry":"","future":1},"port_policy":{"ports":[{"port":1,"pp":false,"future":2}],"restrict_mode":false,"future":3},"verity_volumes":[{"source":"","target":"","verity_root":"","future":4}]}`, `{"runner":"bash","swap_size":123,"init_script":"hello"}`} {
		var compose AppCompose
		if err := json.Unmarshal([]byte(raw), &compose); err != nil {
			t.Error(err)
			continue
		}
		got, err := GetComposeHash(compose)
		if err != nil {
			t.Error(err)
			continue
		}
		wantRaw := raw
		switch raw {
		case `{"runner":"docker-compose","key_provider_id":"","allowed_envs":[],"public_logs":false,"requirements":null}`:
			wantRaw = `{"runner":"docker-compose","key_provider_id":"","allowed_envs":[],"public_logs":false}`
		case `{"runner":"docker-compose","requirements":{"health_check":false,"ephemeral_data_disk":false,"launch_token_hash":""},"docker_config":{"registry":"","future":1},"port_policy":{"ports":[{"port":1,"pp":false,"future":2}],"restrict_mode":false,"future":3},"verity_volumes":[{"source":"","target":"","verity_root":"","future":4}]}`:
			wantRaw = `{"runner":"docker-compose","requirements":{"launch_token_hash":""},"docker_config":{"registry":"","future":1},"port_policy":{"ports":[{"port":1,"pp":false,"future":2}],"restrict_mode":false,"future":3},"verity_volumes":[{"source":"","target":"","verity_root":"","future":4}]}`
		}
		if want := hashOfRawJSON(t, wantRaw); got != want {
			t.Errorf("%s: got %s want %s", raw, got, want)
		}
	}
}

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

// `gpu_policy` is nested, so it needs its own passthrough: without one, a
// sub-field this SDK has not caught up with is dropped a level down where the
// AppCompose-level Extra never sees it, and the resulting digest is wrong with
// nothing to signal it.
func TestAnUnknownGpuPolicyFieldStillReachesTheHash(t *testing.T) {
	withUnknown := `{"runner":"docker-compose","requirements":{"gpu_policy":{"attest_gpu":true,"min_gpu_count":2}}}`
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
		t.Fatalf("an unknown gpu_policy field was dropped.\n got=%s\nwant=%s\nre-encoded: %s", got, want, reencoded)
	}
}

// The canonical form is the bytes the other SDKs produce, and `json.Marshal`
// HTML-escapes `<`, `>` and `&` into `\u003c`, `\u003e` and `\u0026`. Rust,
// Python and JS all leave them alone, so a `&&` in a compose file used to be
// enough to make this SDK the only one computing a digest the chain would not
// be asked to whitelist.
//
// The fixture has to keep carrying one of those three characters or this stops
// testing anything.
func TestHTMLCharactersAreNotEscaped(t *testing.T) {
	compose := AppCompose{
		Runner:            "docker-compose",
		DockerComposeFile: "services:\n  w:\n    image: x && y\n",
	}
	got, err := GetComposeHash(compose)
	if err != nil {
		t.Fatal(err)
	}
	// Written out rather than derived, so this pins the bytes and not the code
	// that produced them.
	canonical := `{"docker_compose_file":"services:\n  w:\n    image: x && y\n","runner":"docker-compose"}`
	sum := sha256.Sum256([]byte(canonical))
	if want := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("the canonical form diverged from the other SDKs.\n got=%s\nwant=%s", got, want)
	}
}

// encoding/json escapes U+2028 and U+2029 even with HTML escaping off; the
// other SDKs write them raw. The fixture also carries the six characters
// `\u2028`, whose backslash is escaped, so they must come out as `\\u2028`.
func TestLineSeparatorsAreNotEscaped(t *testing.T) {
	compose := AppCompose{
		Runner:            "docker-compose",
		DockerComposeFile: "a\u2028b\u2029c \\u2028",
	}
	got, err := GetComposeHash(compose)
	if err != nil {
		t.Fatal(err)
	}
	canonical := "{\"docker_compose_file\":\"a\u2028b\u2029c \\\\u2028\",\"runner\":\"docker-compose\"}"
	sum := sha256.Sum256([]byte(canonical))
	if want := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("the canonical form diverged from the other SDKs.\n got=%s\nwant=%s", got, want)
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

func TestComposeNullThenSetTypedField(t *testing.T) {
	var compose AppCompose
	if err := json.Unmarshal([]byte(`{"name":null}`), &compose); err != nil {
		t.Fatal(err)
	}
	compose.Name = "foo"
	data, err := json.Marshal(compose)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["name"] != "foo" {
		t.Fatalf("name = %v, want foo", got["name"])
	}
}

func TestTypedInitScriptAndSwapSize(t *testing.T) {
	for _, raw := range []string{`{"runner":"bash","init_script":"hello","swap_size":123}`, `{"runner":"bash","init_script":["a","b"],"swap_size":"2G"}`} {
		var compose AppCompose
		if err := json.Unmarshal([]byte(raw), &compose); err != nil {
			t.Fatal(err)
		}
		if len(compose.InitScript.Scripts) == 0 {
			t.Fatal("missing scripts")
		}
		if compose.SwapSize.Number == "" && compose.SwapSize.String == nil {
			t.Fatal("missing swap size")
		}
		got, err := GetComposeHash(compose)
		if err != nil {
			t.Fatal(err)
		}
		if want := hashOfRawJSON(t, raw); got != want {
			t.Fatalf("got %s want %s", got, want)
		}
	}
	data, err := json.Marshal(AppCompose{})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"init_script", "swap_size"} {
		if _, ok := fields[key]; ok {
			t.Errorf("zero value included %s", key)
		}
	}
}

func TestRustOptionNullAndSkippedFalse(t *testing.T) {
	cases := []struct{ name, input, want string }{
		{"app_omitted_options", `{"runner":"bash","snapshotter":null,"requirements":null}`, `{"runner":"bash"}`},
		{"app_kept_options", `{"runner":"bash","docker_compose_file":null,"key_provider":null,"storage_fs":null}`, `{"runner":"bash","docker_compose_file":null,"key_provider":null,"storage_fs":null}`},
		{"requirements_omitted_options", `{"runner":"bash","requirements":{"platforms":null,"tdx_measure_acpi_tables":null,"launch_token_hash":null,"health_status_file":null}}`, `{"runner":"bash","requirements":{}}`},
		{"requirements_false", `{"runner":"bash","requirements":{"health_check":false,"ephemeral_data_disk":false}}`, `{"runner":"bash","requirements":{}}`},
		{"gpu_rego", `{"runner":"bash","requirements":{"gpu_policy":{"rego":null}}}`, `{"runner":"bash","requirements":{"gpu_policy":{}}}`},
		{"docker_options", `{"runner":"bash","docker_config":{"registry":null,"username":null,"token_key":null}}`, `{"runner":"bash","docker_config":{"registry":null,"username":null,"token_key":null}}`},
		{"non_option_null", `{"runner":"bash","name":null,"port_policy":{"restrict_mode":null},"requirements":{"health_check":null}}`, `{"runner":"bash","name":null,"port_policy":{"restrict_mode":null},"requirements":{"health_check":null}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var compose AppCompose
			if err := json.Unmarshal([]byte(tc.input), &compose); err != nil {
				t.Fatal(err)
			}
			got, err := GetComposeHash(compose)
			if err != nil {
				t.Fatal(err)
			}
			if want := hashOfRawJSON(t, tc.want); got != want {
				data, _ := json.Marshal(compose)
				t.Fatalf("got %s want %s", data, tc.want)
			}
		})
	}
}
