// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack

import "testing"

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
