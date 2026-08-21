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
			OsVersion:   ">=0.6.1",
			HealthCheck: &HealthCheck{Enabled: true, HealthFile: "/dstack/health"},
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

// health_file selects which source the verdict comes from, so it is not
// cosmetic.
func TestHealthFileIsPartOfTheHash(t *testing.T) {
	mk := func(file string) AppCompose {
		return AppCompose{
			Runner:       "docker-compose",
			Requirements: &Requirements{HealthCheck: &HealthCheck{Enabled: true, HealthFile: file}},
		}
	}
	a, err := GetComposeHash(mk(""))
	if err != nil {
		t.Fatal(err)
	}
	b, err := GetComposeHash(mk("/dstack/health"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("health_file does not reach the compose hash")
	}
}
