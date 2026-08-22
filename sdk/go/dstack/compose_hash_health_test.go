// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack

import "testing"

// A field the struct does not declare is dropped on marshal, which produces a
// compose hash that does not match the app-compose actually deployed -- and
// that hash is what gets whitelisted on chain.
func TestHealthCheckRequirementChangesTheHash(t *testing.T) {
	plain := AppCompose{
		Runner:            "docker-compose",
		DockerComposeFile: "docker-compose.yml",
		Requirements:      &Requirements{OsVersion: ">=0.6.1"},
	}
	gated := AppCompose{
		Runner:            "docker-compose",
		DockerComposeFile: "docker-compose.yml",
		Requirements: &Requirements{
			OsVersion:        ">=0.6.1",
			HealthCheck:      true,
			HealthStatusFile: strPtr("/dstack/health"),
		},
	}
	a, err := GetComposeHash(plain)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GetComposeHash(gated)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("requirements.health_check does not reach the compose hash")
	}
}

// Opting out is what every app did before this feature existed, so it has to
// keep hashing that way; the guest's Rust types skip a false `health_check`,
// and a Go `false` that serialized would fork the digest.
func TestDisabledHealthCheckHashesAsAbsent(t *testing.T) {
	disabled := AppCompose{
		Runner:       "docker-compose",
		Requirements: &Requirements{OsVersion: ">=0.6.1", HealthCheck: false},
	}
	got, err := GetComposeHash(disabled)
	if err != nil {
		t.Fatal(err)
	}
	want := hashOfRawJSON(t, `{"runner":"docker-compose","requirements":{"os_version":">=0.6.1"}}`)
	if got != want {
		t.Fatalf("a false health_check must not appear in the manifest.\n got=%s\nwant=%s", got, want)
	}
}

// health_status_file selects which source the verdict comes from, so it is not
// cosmetic.
func TestHealthStatusFileIsPartOfTheHash(t *testing.T) {
	mk := func(file *string) AppCompose {
		return AppCompose{
			Runner:       "docker-compose",
			Requirements: &Requirements{HealthCheck: true, HealthStatusFile: file},
		}
	}
	a, err := GetComposeHash(mk(nil))
	if err != nil {
		t.Fatal(err)
	}
	b, err := GetComposeHash(mk(strPtr("/dstack/health")))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("health_status_file does not reach the compose hash")
	}
}

// `omitempty` on a plain string collapses these two, which Rust, Python and JS
// keep distinct -- so a Go user re-hashing an app-compose that carries an empty
// health_status_file would get a digest the other SDKs disagree with.
func TestEmptyHealthStatusFileIsDistinctFromAbsent(t *testing.T) {
	mk := func(file *string) AppCompose {
		return AppCompose{
			Runner:       "docker-compose",
			Requirements: &Requirements{HealthCheck: true, HealthStatusFile: file},
		}
	}
	absent, err := GetComposeHash(mk(nil))
	if err != nil {
		t.Fatal(err)
	}
	empty, err := GetComposeHash(mk(strPtr("")))
	if err != nil {
		t.Fatal(err)
	}
	if absent == empty {
		t.Fatal("an empty health_status_file must not hash the same as an absent one")
	}
}

func strPtr(s string) *string { return &s }
