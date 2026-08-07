// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
)

// KeyProviderKind represents the key provider type
type KeyProviderKind string

const (
	KeyProviderNone  KeyProviderKind = "none"
	KeyProviderKMS   KeyProviderKind = "kms"
	KeyProviderLocal KeyProviderKind = "local"
	KeyProviderTPM   KeyProviderKind = "tpm"
)

// EventLogVersion selects the event log digest format. It is serialized as a
// number, matching dstack-types EventLogVersion.
type EventLogVersion int

const (
	// EventLogVersionV1 is the legacy binary digest and the implicit default.
	EventLogVersionV1 EventLogVersion = 1
	// EventLogVersionV2 is the JCS canonical JSON digest.
	EventLogVersionV2 EventLogVersion = 2
)

// PortAttrs holds the gateway policy for a single port.
type PortAttrs struct {
	Port uint16 `json:"port"`
	// PP asks the gateway to send a PROXY protocol header on outbound
	// connections to this port.
	PP bool `json:"pp"`
}

// PortPolicy is the per-port policy consumed by the gateway.
type PortPolicy struct {
	Ports []PortAttrs `json:"ports"`
	// RestrictMode makes the gateway forward only to ports listed in Ports and
	// reject everything else at TCP-accept time.
	RestrictMode bool `json:"restrict_mode"`
}

// VerityVolume is a pre-baked, read-only dm-verity volume attached to the CVM.
type VerityVolume struct {
	// Source is a bare image file name resolved by the VMM under its volumes dir.
	Source string `json:"source"`
	// VerityRoot is the hex dm-verity root hash: the volume's content identity.
	VerityRoot string `json:"verity_root"`
	// Target is the absolute mount path inside the guest.
	Target string `json:"target"`
}

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

// Requirements represents guest-side requirements.
type Requirements struct {
	OsVersion            string                 `json:"os_version,omitempty"`
	Platforms            *[]RequirementPlatform `json:"platforms,omitempty"`
	TdxMeasureAcpiTables *bool                  `json:"tdx_measure_acpi_tables,omitempty"`
	LaunchTokenHash      string                 `json:"launch_token_hash,omitempty"`
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
	// InitScript holds bash scripts run before the application runner starts.
	InitScript []string `json:"init_script,omitempty"`
	// StorageFS selects the guest data filesystem ("ext4" or "zfs").
	StorageFS string `json:"storage_fs,omitempty"`
	// SwapSize is a human-readable size such as "2G". dstack-types serializes
	// this field as a string in JSON, not as a byte count.
	SwapSize string `json:"swap_size,omitempty"`
	// EventLogVersion selects the event log digest format. Leave it unset for
	// v1, which dstack-types omits from the document.
	EventLogVersion EventLogVersion `json:"event_log_version,omitempty"`
	// PortPolicy is optional here even though dstack-types always serializes
	// it: emitting an empty policy for an app that does not use one would
	// change that app's compose hash.
	PortPolicy *PortPolicy `json:"port_policy,omitempty"`
	// VerityVolumes are measured as part of these compose bytes, so the guest
	// only mounts content matching the attested app.
	VerityVolumes   []VerityVolume `json:"verity_volumes,omitempty"`
	BashScript      string         `json:"bash_script,omitempty"`       // Legacy
	PreLaunchScript string         `json:"pre_launch_script,omitempty"` // Legacy

	// Extra carries app_compose keys this SDK version does not declare.
	//
	// The compose hash is taken over the whole app_compose document, so a key
	// dropped during marshalling changes the resulting app identity. The
	// JavaScript SDK (index signature) and the Python SDK (**kwargs) both keep
	// unknown keys; Go marshals a struct, which silently discards them. Extra
	// closes that gap, so a compose using a field newer than this SDK still
	// hashes to the same value as it does everywhere else.
	//
	// Keys are merged into the top-level object on marshal and collected from
	// it on unmarshal. A key that is already a declared field is rejected
	// rather than silently overriding it.
	Extra map[string]any `json:"-"`
}

// declaredComposeFields returns the JSON names of every declared AppCompose
// field, including those omitempty would leave out of a given document.
var declaredComposeFields = sync.OnceValue(func() map[string]struct{} {
	names := make(map[string]struct{})
	t := reflect.TypeOf(AppCompose{})
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		names[name] = struct{}{}
	}
	return names
})

// MarshalJSON emits the declared fields and then merges Extra into the same
// object.
func (a AppCompose) MarshalJSON() ([]byte, error) {
	type plain AppCompose
	encoded, err := json.Marshal(plain(a))
	if err != nil {
		return nil, err
	}
	if len(a.Extra) == 0 {
		return encoded, nil
	}

	var merged map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &merged); err != nil {
		return nil, err
	}

	declared := declaredComposeFields()
	for key, value := range a.Extra {
		if _, isDeclared := declared[key]; isDeclared {
			return nil, fmt.Errorf("dstack: app_compose Extra key %q collides with a declared field; set the field instead", key)
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("dstack: app_compose Extra key %q: %w", key, err)
		}
		merged[key] = raw
	}
	return json.Marshal(merged)
}

// UnmarshalJSON decodes the declared fields and collects everything else into
// Extra, so a document can be re-hashed without losing keys.
func (a *AppCompose) UnmarshalJSON(data []byte) error {
	type plain AppCompose
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*a = AppCompose(decoded)

	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}

	declared := declaredComposeFields()
	extra := make(map[string]any)
	for key, raw := range all {
		if _, isDeclared := declared[key]; isDeclared {
			continue
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("dstack: app_compose field %q: %w", key, err)
		}
		extra[key] = value
	}
	if len(extra) > 0 {
		a.Extra = extra
	}
	return nil
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

// toDeterministicJSON converts the structure to deterministic JSON.
//
// encoding/json escapes <, > and & as \u003c, \u003e and \u0026 unless told
// otherwise, while JSON.stringify and json.dumps emit them literally. Those
// characters are ordinary in a compose document — ">=0.6.0" in
// requirements.os_version, "sh -c \"migrate && serve\"" in
// docker_compose_file — so the escaping alone made Go disagree with every other
// SDK about an app's compose hash. Encoder.SetEscapeHTML(false) turns it off;
// Encoder also appends a newline, which is not part of the hashed bytes.
func toDeterministicJSON(v interface{}) (string, error) {
	sorted := sortKeys(v)

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(sorted); err != nil {
		return "", err
	}
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
