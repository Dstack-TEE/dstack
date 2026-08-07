// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack

import (
	"encoding/json"
	"testing"
)

// The expected hashes below are reference values produced by the JavaScript
// SDK (sdk/js/src/get-compose-hash.ts), which CROSS_LANGUAGE_CONSISTENCY_TESTING.md
// designates as the canonical implementation. Each one was additionally
// cross-checked against the Python SDK (sdk/python/src/dstack_sdk/get_compose_hash.py).
//
// A compose hash is the identity of a deployed app: if Go disagrees with the
// other SDKs by a single byte, an app deployed through Go fails attestation.
// These vectors are the guard against that.

func boolPtr(v bool) *bool { return &v }

func TestGetComposeHashMatchesJSReference(t *testing.T) {
	tests := []struct {
		name      string
		compose   AppCompose
		normalize bool
		want      string
	}{
		{
			name:    "minimal",
			compose: AppCompose{Runner: "docker-compose"},
			want:    "1120e42a7b5f2ca50128696ea414771441b4fa92373427108a7173181cc80b55",
		},
		{
			name: "docker compose file",
			compose: AppCompose{
				Runner:            "docker-compose",
				DockerComposeFile: "services:\n  app:\n    image: nginx\n",
			},
			want: "1ce6eb200cb550901bf9d1f3b30d3a2a678ae6a7dc7d78ff226dd41d78dbb355",
		},
		{
			name: "full legacy field set",
			compose: AppCompose{
				ManifestVersion:         1,
				Name:                    "my-app",
				Runner:                  "docker-compose",
				DockerComposeFile:       "docker-compose.yml",
				DockerConfig:            &DockerConfig{Registry: "docker.io", Username: "myuser", TokenKey: "token123"},
				Features:                []string{"legacy-feature"},
				PublicLogs:              boolPtr(true),
				PublicSysinfo:           boolPtr(false),
				PublicTcbinfo:           boolPtr(true),
				KmsEnabled:              boolPtr(true),
				GatewayEnabled:          boolPtr(false),
				TproxyEnabled:           boolPtr(true),
				LocalKeyProviderEnabled: boolPtr(true),
				KeyProvider:             KeyProviderKMS,
				KeyProviderID:           "abcd1234",
				AllowedEnvs:             []string{"NODE_ENV", "PORT"},
				NoInstanceID:            boolPtr(false),
				SecureTime:              boolPtr(true),
				PreLaunchScript:         "echo 'Starting...'",
			},
			want: "9e16e3de034ac9537fd436c3a579785450dde60508c288ffc11bd90adfbbdcdf",
		},
		{
			name: "bash runner drops docker_compose_file when normalized",
			compose: AppCompose{
				Runner:            "bash",
				BashScript:        "start.sh",
				DockerComposeFile: "docker-compose.yml",
			},
			normalize: true,
			want:      "75a6f53f70c26c8f7b545f48c2f5ef2f76c27d13f7034be1021cf25f5d9853d2",
		},
		{
			name: "docker runner drops bash_script when normalized",
			compose: AppCompose{
				Runner:            "docker-compose",
				DockerComposeFile: "docker-compose.yml",
				BashScript:        "start.sh",
			},
			normalize: true,
			want:      "6148eabae40413a5c15aeab33343e7a219edc0cda2c2556add9a96ec76d61b11",
		},
		{
			name: "empty pre_launch_script is dropped",
			compose: AppCompose{
				Runner:            "docker-compose",
				DockerComposeFile: "docker-compose.yml",
				PreLaunchScript:   "",
			},
			normalize: true,
			want:      "6148eabae40413a5c15aeab33343e7a219edc0cda2c2556add9a96ec76d61b11",
		},
		{
			name: "requirements",
			compose: AppCompose{
				Runner:            "docker-compose",
				DockerComposeFile: "docker-compose.yml",
				Requirements: &Requirements{
					OsVersion:            "0.5.4",
					Platforms:            &[]RequirementPlatform{RequirementPlatformTdx, RequirementPlatformGcpTdx},
					TdxMeasureAcpiTables: boolPtr(true),
					LaunchTokenHash:      "deadbeef",
				},
			},
			want: "36348dde5e4c20fc09d7a2399405866301dd6afd5e75978b3876270543470406",
		},
		{
			name: "nerdctl snapshotter",
			compose: AppCompose{
				Runner:            "nerdctl-compose",
				DockerComposeFile: "docker-compose.yml",
				Snapshotter:       "stargz",
			},
			want: "872e2833c1d8915bb61718f8bebb018ece4244e5e6d1d3bb611375b475cf9d4f",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetComposeHash(tt.compose, tt.normalize)
			if err != nil {
				t.Fatalf("GetComposeHash: %v", err)
			}
			if got != tt.want {
				t.Fatalf("hash = %s, want %s (JS reference)", got, tt.want)
			}
		})
	}
}

func TestGetComposeHashIsDeterministic(t *testing.T) {
	compose := AppCompose{
		Runner:            "docker-compose",
		DockerComposeFile: "docker-compose.yml",
		AllowedEnvs:       []string{"NODE_ENV", "PORT"},
	}

	first, err := GetComposeHash(compose, false)
	if err != nil {
		t.Fatalf("GetComposeHash: %v", err)
	}
	for i := 0; i < 10; i++ {
		got, err := GetComposeHash(compose, false)
		if err != nil {
			t.Fatalf("GetComposeHash: %v", err)
		}
		if got != first {
			t.Fatalf("hash changed between calls: %s then %s", first, got)
		}
	}
}

func TestGetComposeHashDistinguishesDifferentComposes(t *testing.T) {
	a, err := GetComposeHash(AppCompose{Runner: "docker-compose", DockerComposeFile: "docker-compose.yml"}, false)
	if err != nil {
		t.Fatalf("GetComposeHash: %v", err)
	}
	b, err := GetComposeHash(AppCompose{Runner: "bash", BashScript: "start.sh"}, false)
	if err != nil {
		t.Fatalf("GetComposeHash: %v", err)
	}
	if a == b {
		t.Fatal("different composes produced the same hash")
	}
}

// TestGetComposeHashPassesUnknownFieldsThrough covers the fields Go does not
// declare. The JS SDK's AppCompose carries an index signature and the Python
// SDK accepts **kwargs, so both hash unknown keys. Go marshals a struct, which
// silently drops them — producing a hash that disagrees with every other SDK
// for the same compose.
func TestGetComposeHashPassesUnknownFieldsThrough(t *testing.T) {
	tests := []struct {
		name              string
		dockerComposeFile string
		extra             map[string]any
		want              string
	}{
		{
			// Stands in for whatever dstack-types adds next: a field this SDK
			// version has never heard of still has to reach the hash.
			name:              "field newer than this SDK",
			dockerComposeFile: "docker-compose.yml",
			extra: map[string]any{
				"future_policy": map[string]any{
					"enabled": true,
					"limits":  []any{1, 2, 3},
				},
			},
			want: "c43b5c245b0f5ee1380784e8edc1180846d6f1fdf279a7a80174466647e049b5",
		},
		{
			name:  "utf8 values",
			extra: map[string]any{"text": "你好世界", "description": "🚀 Deploy"},
			want:  "735ef5a6a9ac2405dda08948b551c9c7b529f4e4b790d6784ff5e2ee2e394f41",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compose := AppCompose{
				Runner:            "docker-compose",
				DockerComposeFile: tt.dockerComposeFile,
				Extra:             tt.extra,
			}
			got, err := GetComposeHash(compose, false)
			if err != nil {
				t.Fatalf("GetComposeHash: %v", err)
			}
			if got != tt.want {
				t.Fatalf("hash = %s, want %s (JS reference)", got, tt.want)
			}
		})
	}
}

// TestExtraCannotShadowDeclaredFields guards the one way Extra could corrupt a
// hash: a key that also exists as a struct field would otherwise be emitted
// twice, and which one wins would depend on map iteration order.
func TestExtraCannotShadowDeclaredFields(t *testing.T) {
	_, err := GetComposeHash(AppCompose{
		Runner: "docker-compose",
		Extra:  map[string]any{"runner": "bash"},
	}, false)
	if err == nil {
		t.Fatal("GetComposeHash accepted an Extra key shadowing a declared field")
	}
}

// TestAppComposeRoundTripsUnknownFields covers decoding: an app_compose read
// from the wire must keep the fields this SDK version does not know about, or
// re-hashing it would produce a different app identity.
func TestAppComposeRoundTripsUnknownFields(t *testing.T) {
	// Key order is deliberately scrambled: the hash must not depend on it.
	// port_policy is declared, future_policy is not — both must survive.
	raw := `{"runner":"docker-compose","docker_compose_file":"docker-compose.yml","future_policy":{"enabled":true},"port_policy":{"restrict_mode":true,"ports":[{"pp":true,"port":443},{"pp":false,"port":8080}]}}`

	var compose AppCompose
	if err := json.Unmarshal([]byte(raw), &compose); err != nil {
		t.Fatalf("unmarshal app compose: %v", err)
	}
	if compose.Runner != "docker-compose" {
		t.Fatalf("Runner = %q, want docker-compose", compose.Runner)
	}
	if compose.PortPolicy == nil {
		t.Fatal("declared port_policy dropped during decoding")
	}
	if _, ok := compose.Extra["future_policy"]; !ok {
		t.Fatal("undeclared future_policy dropped during decoding")
	}

	got, err := GetComposeHash(compose, false)
	if err != nil {
		t.Fatalf("GetComposeHash: %v", err)
	}
	want := "de89dda5b47f62d463757b3ffd2aa1dd4af08401683717bdd1244649f18ba40f"
	if got != want {
		t.Fatalf("hash after round trip = %s, want %s", got, want)
	}
}

// TestGetComposeHashCoversFieldsAddedSinceV010 pins the app_compose fields the
// Go struct gained to match dstack-types. Each expected hash is the JS
// reference value for the same document, so a wrong JSON tag or wire type
// (swap_size is a human-readable string, not a byte count) fails here rather
// than at attestation time.
func TestGetComposeHashCoversFieldsAddedSinceV010(t *testing.T) {
	tests := []struct {
		name    string
		compose AppCompose
		want    string
	}{
		{
			name: "port_policy",
			compose: AppCompose{
				Runner:            "docker-compose",
				DockerComposeFile: "docker-compose.yml",
				PortPolicy: &PortPolicy{
					Ports:        []PortAttrs{{Port: 443, PP: true}, {Port: 8080, PP: false}},
					RestrictMode: true,
				},
			},
			want: "6be823decce06179698ee6fd087d82951c21ba6a24ba6419a6801b0be1ce2bdc",
		},
		{
			name: "empty port_policy still serializes its keys",
			compose: AppCompose{
				Runner:     "docker-compose",
				PortPolicy: &PortPolicy{Ports: []PortAttrs{}, RestrictMode: false},
			},
			want: "3b647a53cded50c2d33f29bc07dd2ce7871d08cdff6e41d76f915d262c58bf57",
		},
		{
			name:    "storage_fs and swap_size",
			compose: AppCompose{Runner: "docker-compose", StorageFS: "zfs", SwapSize: "2G"},
			want:    "b140f74b52ae10dc42efe16e4368784b60f755ada3781a0be8b8aafae6a6ab86",
		},
		{
			name:    "init_script",
			compose: AppCompose{Runner: "docker-compose", InitScript: []string{"echo one", "echo two"}},
			want:    "8c35247d5b685a8d24b97182f3b0a4e3c1ab6d8eecee6704424a0de0dd8a66a3",
		},
		{
			name:    "event_log_version",
			compose: AppCompose{Runner: "docker-compose", EventLogVersion: EventLogVersionV2},
			want:    "8d1f7a3b6a6fc64236667a69c7618c5075d85d4c3afd8fb9a4b0c733b60ae8f5",
		},
		{
			name: "verity_volumes",
			compose: AppCompose{
				Runner: "docker-compose",
				VerityVolumes: []VerityVolume{{
					Source:     "data.img",
					VerityRoot: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
					Target:     "/mnt/data",
				}},
			},
			want: "3eb00892f370ab31f854172991b655a0880ccb7786d121dfb75cbd9b038df19f",
		},
		{
			name:    "tpm key provider",
			compose: AppCompose{Runner: "docker-compose", KeyProvider: KeyProviderTPM, KeyProviderID: "aabb"},
			want:    "e4bfbeaf851f73b873f04e74cc5699668dc282bd96e15dbf0ab1e5e05cc2ca76",
		},
		{
			name: "all new fields together",
			compose: AppCompose{
				ManifestVersion:   "3",
				Name:              "my-app",
				Runner:            "docker-compose",
				DockerComposeFile: "docker-compose.yml",
				InitScript:        []string{"echo hello"},
				StorageFS:         "ext4",
				SwapSize:          "1G",
				EventLogVersion:   EventLogVersionV2,
				PortPolicy: &PortPolicy{
					Ports:        []PortAttrs{{Port: 443, PP: true}},
					RestrictMode: false,
				},
				VerityVolumes: []VerityVolume{{
					Source:     "a.img",
					VerityRoot: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
					Target:     "/mnt/a",
				}},
				KeyProvider: KeyProviderTPM,
			},
			want: "24e4d4f046fda84fba03df6199ad41fdcb67482e86f3705e46c28be8769b895a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetComposeHash(tt.compose, false)
			if err != nil {
				t.Fatalf("GetComposeHash: %v", err)
			}
			if got != tt.want {
				t.Fatalf("hash = %s, want %s (JS reference)", got, tt.want)
			}
		})
	}
}

// TestUnsetNewFieldsDoNotChangeExistingHashes guards the upgrade path: a
// compose that predates these fields must keep hashing to the value it had
// before they were declared, or every already-deployed app changes identity.
func TestUnsetNewFieldsDoNotChangeExistingHashes(t *testing.T) {
	got, err := GetComposeHash(AppCompose{Runner: "docker-compose"}, false)
	if err != nil {
		t.Fatalf("GetComposeHash: %v", err)
	}
	const want = "1120e42a7b5f2ca50128696ea414771441b4fa92373427108a7173181cc80b55"
	if got != want {
		t.Fatalf("minimal compose hash = %s, want %s", got, want)
	}
}

// TestNewFieldsDecodeIntoDeclaredFields checks the fields moved out of Extra:
// a document carrying them must now populate the struct.
func TestNewFieldsDecodeIntoDeclaredFields(t *testing.T) {
	raw := `{"runner":"docker-compose","port_policy":{"ports":[{"port":443,"pp":true}],"restrict_mode":true},"swap_size":"2G","storage_fs":"zfs","event_log_version":2,"init_script":["echo one"]}`

	var compose AppCompose
	if err := json.Unmarshal([]byte(raw), &compose); err != nil {
		t.Fatalf("unmarshal app compose: %v", err)
	}
	if compose.PortPolicy == nil || !compose.PortPolicy.RestrictMode {
		t.Fatalf("PortPolicy = %+v, want restrict_mode true", compose.PortPolicy)
	}
	if len(compose.PortPolicy.Ports) != 1 || compose.PortPolicy.Ports[0].Port != 443 || !compose.PortPolicy.Ports[0].PP {
		t.Fatalf("PortPolicy.Ports = %+v, want one entry 443/pp", compose.PortPolicy.Ports)
	}
	if compose.SwapSize != "2G" || compose.StorageFS != "zfs" {
		t.Fatalf("SwapSize/StorageFS = %q/%q, want 2G/zfs", compose.SwapSize, compose.StorageFS)
	}
	if compose.EventLogVersion != EventLogVersionV2 {
		t.Fatalf("EventLogVersion = %d, want 2", compose.EventLogVersion)
	}
	if len(compose.InitScript) != 1 {
		t.Fatalf("InitScript = %v, want one entry", compose.InitScript)
	}
	if len(compose.Extra) != 0 {
		t.Fatalf("Extra = %v, want empty now that these fields are declared", compose.Extra)
	}
}
