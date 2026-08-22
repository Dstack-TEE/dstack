// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
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

// GpuPolicy is the application GPU policy applied before key provisioning.
type GpuPolicy struct {
	AttestGpu         *bool   `json:"attest_gpu,omitempty"`
	Rego              *string `json:"rego,omitempty"`
	AllowDevtools     *bool   `json:"allow_devtools,omitempty"`
	AllowDebug        *bool   `json:"allow_debug,omitempty"`
	AllowInsecureBoot *bool   `json:"allow_insecure_boot,omitempty"`

	// Extra carries fields this SDK does not know; see AppCompose.Extra.
	Extra map[string]interface{} `json:"-"`
}

// Requirements represents guest-side requirements.
type Requirements struct {
	OsVersion            string                 `json:"os_version,omitempty"`
	Platforms            *[]RequirementPlatform `json:"platforms,omitempty"`
	TdxMeasureAcpiTables *bool                  `json:"tdx_measure_acpi_tables,omitempty"`
	LaunchTokenHash      string                 `json:"launch_token_hash,omitempty"`

	// HealthCheck opts into gateway health gating. `omitempty` is the point:
	// the guest's Rust types skip a false `health_check`, so an app that opts
	// out has to hash exactly as it did before this field existed.
	HealthCheck bool `json:"health_check,omitempty"`
	// HealthStatusFile is a pointer because `omitempty` on a string cannot tell
	// an absent field from an empty one, and Rust, Python and JS all can.
	// Re-hashing an app-compose that carries `"health_status_file": ""` would
	// otherwise yield a different digest here than in the other SDKs -- and
	// that digest is what gets whitelisted on chain. TdxMeasureAcpiTables is a
	// pointer for the same reason.
	HealthStatusFile *string `json:"health_status_file,omitempty"`

	GpuPolicy *GpuPolicy `json:"gpu_policy,omitempty"`

	// Extra carries fields this SDK does not know; see AppCompose.Extra.
	Extra map[string]interface{} `json:"-"`
}

// PortAttrs is the per-port policy the gateway applies.
type PortAttrs struct {
	Port uint16 `json:"port"`
	Pp   bool   `json:"pp,omitempty"`
}

// PortPolicy is the per-port policy consumed by the gateway.
type PortPolicy struct {
	Ports        []PortAttrs `json:"ports,omitempty"`
	RestrictMode bool        `json:"restrict_mode,omitempty"`
}

// VerityVolume is a read-only, dm-verity-protected volume pre-seeded into the CVM.
type VerityVolume struct {
	Source string `json:"source"`
	// VerityRoot is the dm-verity root hash, hex encoded.
	VerityRoot string `json:"verity_root"`
	Target     string `json:"target"`
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
	InitScript              []string        `json:"init_script,omitempty"`
	StorageFs               string          `json:"storage_fs,omitempty"`
	// SwapSize is a human size string, e.g. "2G", matching what the guest reads.
	SwapSize        string         `json:"swap_size,omitempty"`
	EventLogVersion *uint32        `json:"event_log_version,omitempty"`
	PortPolicy      *PortPolicy    `json:"port_policy,omitempty"`
	VerityVolumes   []VerityVolume `json:"verity_volumes,omitempty"`
	BashScript      string         `json:"bash_script,omitempty"`       // Legacy
	PreLaunchScript string         `json:"pre_launch_script,omitempty"` // Legacy

	// Extra carries fields this SDK does not have a typed name for.
	//
	// A closed struct silently drops what it does not know, and the value this
	// package computes is a compose hash that gets whitelisted on chain -- so a
	// dropped field means the digest describes an app-compose that is not the
	// one being deployed, with nothing anywhere to notice. Unmarshalling puts
	// unrecognised keys here and marshalling puts them back, so a guest that
	// gains a field before this SDK does still hashes correctly.
	//
	// Keys that collide with a declared field are ignored on marshal; the typed
	// field wins.
	Extra map[string]interface{} `json:"-"`
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
//
// HTML escaping is off. `json.Marshal` would write `>=0.6.1` as `\u003e=0.6.1`,
// which is valid JSON and a different byte string -- so an os_version bound, or
// a `&&` in a compose file, silently gave Go a digest that Rust, Python and JS
// never produce, on the value that gets whitelisted on chain.
func toDeterministicJSON(v interface{}) (string, error) {
	sorted := sortKeys(v)
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(sorted); err != nil {
		return "", err
	}
	// Encode appends a newline that Marshal does not.
	return strings.TrimSuffix(buf.String(), "\n"), nil
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

// marshalWithExtra merges a struct's declared fields with its Extra map.
//
// `inner` is a type alias to avoid recursing into the custom MarshalJSON.
func marshalWithExtra(declared interface{}, extra map[string]interface{}) ([]byte, error) {
	encoded, err := json.Marshal(declared)
	if err != nil {
		return nil, err
	}
	if len(extra) == 0 {
		return encoded, nil
	}
	merged := map[string]interface{}{}
	if err := json.Unmarshal(encoded, &merged); err != nil {
		return nil, err
	}
	for key, value := range extra {
		if _, declared := merged[key]; declared {
			continue
		}
		merged[key] = value
	}
	return json.Marshal(merged)
}

// unmarshalWithExtra fills `declared` and collects everything it did not claim.
func unmarshalWithExtra(data []byte, declared interface{}, known map[string]struct{}) (map[string]interface{}, error) {
	if err := json.Unmarshal(data, declared); err != nil {
		return nil, err
	}
	var all map[string]interface{}
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, err
	}
	var extra map[string]interface{}
	for key, value := range all {
		if _, ok := known[key]; ok {
			continue
		}
		if extra == nil {
			extra = map[string]interface{}{}
		}
		extra[key] = value
	}
	return extra, nil
}

func jsonFieldNames(v interface{}) map[string]struct{} {
	names := map[string]struct{}{}
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name != "" {
			names[name] = struct{}{}
		}
	}
	return names
}

// MarshalJSON writes the declared fields plus anything in Extra.
func (a AppCompose) MarshalJSON() ([]byte, error) {
	type inner AppCompose
	return marshalWithExtra(inner(a), a.Extra)
}

// UnmarshalJSON fills the declared fields and keeps the rest in Extra.
func (a *AppCompose) UnmarshalJSON(data []byte) error {
	type inner AppCompose
	var decoded inner
	extra, err := unmarshalWithExtra(data, &decoded, jsonFieldNames(AppCompose{}))
	if err != nil {
		return err
	}
	*a = AppCompose(decoded)
	a.Extra = extra
	return nil
}

// MarshalJSON writes the declared fields plus anything in Extra.
func (r Requirements) MarshalJSON() ([]byte, error) {
	type inner Requirements
	return marshalWithExtra(inner(r), r.Extra)
}

// UnmarshalJSON fills the declared fields and keeps the rest in Extra.
func (r *Requirements) UnmarshalJSON(data []byte) error {
	type inner Requirements
	var decoded inner
	extra, err := unmarshalWithExtra(data, &decoded, jsonFieldNames(Requirements{}))
	if err != nil {
		return err
	}
	*r = Requirements(decoded)
	r.Extra = extra
	return nil
}

// MarshalJSON writes the declared fields plus anything in Extra.
func (g GpuPolicy) MarshalJSON() ([]byte, error) {
	type inner GpuPolicy
	return marshalWithExtra(inner(g), g.Extra)
}

// UnmarshalJSON fills the declared fields and keeps the rest in Extra.
func (g *GpuPolicy) UnmarshalJSON(data []byte) error {
	type inner GpuPolicy
	var decoded inner
	extra, err := unmarshalWithExtra(data, &decoded, jsonFieldNames(GpuPolicy{}))
	if err != nil {
		return err
	}
	*g = GpuPolicy(decoded)
	g.Extra = extra
	return nil
}
