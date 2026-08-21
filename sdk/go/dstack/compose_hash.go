// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// KeyProviderKind represents the key provider type
type KeyProviderKind string

const (
	KeyProviderNone  KeyProviderKind = "none"
	KeyProviderKMS   KeyProviderKind = "kms"
	KeyProviderLocal KeyProviderKind = "local"
)

// DockerConfig represents Docker configuration
type DockerConfig struct {
	Registry string `json:"registry,omitempty"`
	Username string `json:"username,omitempty"`
	TokenKey string `json:"token_key,omitempty"`
}

// RequirementPlatform represents an allowed guest attestation platform.
type RequirementPlatform string

const (
	RequirementPlatformTdx       RequirementPlatform = "dstack-tdx"
	RequirementPlatformGcpTdx    RequirementPlatform = "dstack-gcp-tdx"
	RequirementPlatformAmdSevSnp RequirementPlatform = "dstack-amd-sev-snp"
	RequirementPlatformNitro     RequirementPlatform = "dstack-nitro-enclave"
)

// HealthCheck represents application health reporting, read by the gateway.
type HealthCheck struct {
	Enabled    bool   `json:"enabled"`
	HealthFile string `json:"health_file,omitempty"`
}

// Requirements represents guest-side requirements.
type Requirements struct {
	OsVersion            string                 `json:"os_version,omitempty"`
	Platforms            *[]RequirementPlatform `json:"platforms,omitempty"`
	TdxMeasureAcpiTables *bool                  `json:"tdx_measure_acpi_tables,omitempty"`
	LaunchTokenHash      string                 `json:"launch_token_hash,omitempty"`
	HealthCheck          *HealthCheck           `json:"health_check,omitempty"`
}

// AppCompose represents the application composition structure
type AppCompose struct {
	ManifestVersion         interface{}     `json:"manifest_version,omitempty"`
	Name                    string          `json:"name,omitempty"`
	Features                []string        `json:"features,omitempty"` // Deprecated
	Runner                  string          `json:"runner"`
	Snapshotter             string          `json:"snapshotter,omitempty"`
	DockerComposeFile       string          `json:"docker_compose_file,omitempty"`
	DockerConfig            *DockerConfig   `json:"docker_config,omitempty"`
	PublicLogs              *bool           `json:"public_logs,omitempty"`
	PublicSysinfo           *bool           `json:"public_sysinfo,omitempty"`
	PublicTcbinfo           *bool           `json:"public_tcbinfo,omitempty"`
	KmsEnabled              *bool           `json:"kms_enabled,omitempty"`
	GatewayEnabled          *bool           `json:"gateway_enabled,omitempty"`
	TproxyEnabled           *bool           `json:"tproxy_enabled,omitempty"` // For backward compatibility
	LocalKeyProviderEnabled *bool           `json:"local_key_provider_enabled,omitempty"`
	KeyProvider             KeyProviderKind `json:"key_provider,omitempty"`
	KeyProviderID           string          `json:"key_provider_id,omitempty"` // hex string
	AllowedEnvs             []string        `json:"allowed_envs,omitempty"`
	NoInstanceID            *bool           `json:"no_instance_id,omitempty"`
	SecureTime              *bool           `json:"secure_time,omitempty"`
	Requirements            *Requirements   `json:"requirements,omitempty"`
	BashScript              string          `json:"bash_script,omitempty"`       // Legacy
	PreLaunchScript         string          `json:"pre_launch_script,omitempty"` // Legacy
}

// preprocessAppCompose removes conflicting fields based on runner type
func preprocessAppCompose(appCompose AppCompose) AppCompose {
	if appCompose.Runner == "bash" {
		appCompose.DockerComposeFile = ""
	} else if appCompose.Runner == "docker-compose" || appCompose.Runner == "nerdctl-compose" {
		appCompose.BashScript = ""
	}

	if appCompose.PreLaunchScript == "" {
		// Remove empty pre_launch_script field for deterministic output
	}

	return appCompose
}

// sortKeys recursively sorts all object keys for deterministic JSON output
func sortKeys(v interface{}) interface{} {
	switch value := v.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		keys := make([]string, 0, len(value))
		for k := range value {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			result[k] = sortKeys(value[k])
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(value))
		for i, item := range value {
			result[i] = sortKeys(item)
		}
		return result
	default:
		return value
	}
}

// toDeterministicJSON converts the structure to deterministic JSON
func toDeterministicJSON(v interface{}) (string, error) {
	sorted := sortKeys(v)
	jsonBytes, err := json.Marshal(sorted)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

// GetComposeHash computes the SHA256 hash of the application composition
func GetComposeHash(appCompose AppCompose, normalize ...bool) (string, error) {
	shouldNormalize := len(normalize) > 0 && normalize[0]

	if shouldNormalize {
		appCompose = preprocessAppCompose(appCompose)
	}

	// Convert to generic map for sorting
	jsonBytes, err := json.Marshal(appCompose)
	if err != nil {
		return "", err
	}

	var genericMap interface{}
	if err := json.Unmarshal(jsonBytes, &genericMap); err != nil {
		return "", err
	}

	manifestStr, err := toDeterministicJSON(genericMap)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256([]byte(manifestStr))
	return hex.EncodeToString(hash[:]), nil
}
