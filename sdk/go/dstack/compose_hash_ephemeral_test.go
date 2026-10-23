// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack

import "testing"

func TestDisabledEphemeralDataDiskHashesAsAbsent(t *testing.T) {
	disabled := AppCompose{
		Runner:       "docker-compose",
		Requirements: &Requirements{LaunchTokenHash: "ff00", EphemeralDataDisk: false},
	}
	got, err := GetComposeHash(disabled)
	if err != nil {
		t.Fatal(err)
	}
	want := hashOfRawJSON(t, `{"runner":"docker-compose","requirements":{"launch_token_hash":"ff00"}}`)
	if got != want {
		t.Fatalf("a false ephemeral_data_disk must not appear in the manifest.\n got=%s\nwant=%s", got, want)
	}
}
