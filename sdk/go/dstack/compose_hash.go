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

	// Extra carries keys this SDK version does not declare. See AppCompose.Extra.
	Extra map[string]any `json:"-"`
}

// PortPolicy is the per-port policy consumed by the gateway.
type PortPolicy struct {
	Ports []PortAttrs `json:"ports"`
	// RestrictMode makes the gateway forward only to ports listed in Ports and
	// reject everything else at TCP-accept time.
	RestrictMode bool `json:"restrict_mode"`

	// Extra carries keys this SDK version does not declare. See AppCompose.Extra.
	Extra map[string]any `json:"-"`
}

// VerityVolume is a pre-baked, read-only dm-verity volume attached to the CVM.
type VerityVolume struct {
	// Source is a bare image file name resolved by the VMM under its volumes dir.
	Source string `json:"source"`
	// VerityRoot is the hex dm-verity root hash: the volume's content identity.
	VerityRoot string `json:"verity_root"`
	// Target is the absolute mount path inside the guest.
	Target string `json:"target"`

	// Extra carries keys this SDK version does not declare. See AppCompose.Extra.
	Extra map[string]any `json:"-"`
}

// DockerConfig represents Docker configuration
type DockerConfig struct {
	Registry string `json:"registry,omitempty"`
	Username string `json:"username,omitempty"`
	TokenKey string `json:"token_key,omitempty"`

	// Extra carries keys this SDK version does not declare. See AppCompose.Extra.
	Extra map[string]any `json:"-"`
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
//
// Every field is omitted when unset so the guest applies its own default. That
// matters most for AttestGPU, whose guest-side default is true: emitting a bare
// false would silently turn off GPU attestation for a caller who only wanted to
// set Rego.
type GpuPolicy struct {
	// AttestGPU requires an attached GPU to pass local TEE attestation before
	// the guest continues booting. Nil leaves the guest default (true) in place.
	AttestGPU *bool `json:"attest_gpu,omitempty"`
	// Rego is an optional Rego v0 policy evaluated against nvattest's claims
	// array. It must define the boolean rule data.policy.nv_match.
	Rego string `json:"rego,omitempty"`
	// AllowDevtools permits NVIDIA DevTools mode, which disables the GPU
	// memory-confidentiality guarantees expected in production.
	AllowDevtools bool `json:"allow_devtools,omitempty"`
	// AllowDebug permits claims whose GPU attestation debug status is enabled.
	AllowDebug bool `json:"allow_debug,omitempty"`
	// AllowInsecureBoot permits claims that do not assert GPU secure boot.
	AllowInsecureBoot bool `json:"allow_insecure_boot,omitempty"`

	// Extra carries keys this SDK version does not declare. See AppCompose.Extra.
	Extra map[string]any `json:"-"`
}

// Requirements represents guest-side requirements.
type Requirements struct {
	OsVersion            string                 `json:"os_version,omitempty"`
	Platforms            *[]RequirementPlatform `json:"platforms,omitempty"`
	TdxMeasureAcpiTables *bool                  `json:"tdx_measure_acpi_tables,omitempty"`
	LaunchTokenHash      string                 `json:"launch_token_hash,omitempty"`
	// GpuPolicy is measured even when absent: the guest parses an omitted
	// field as the default empty policy {} and emits its digest as the
	// gpu-policy-hash launch event.
	GpuPolicy *GpuPolicy `json:"gpu_policy,omitempty"`

	// Extra carries keys this SDK version does not declare. See AppCompose.Extra.
	Extra map[string]any `json:"-"`
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

var declaredFieldCache sync.Map // reflect.Type -> map[string]struct{}

// declaredFieldNames returns the JSON names of every declared field on t,
// including those omitempty would leave out of a given document.
func declaredFieldNames(t reflect.Type) map[string]struct{} {
	if cached, ok := declaredFieldCache.Load(t); ok {
		return cached.(map[string]struct{})
	}
	names := make(map[string]struct{})
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		names[name] = struct{}{}
	}
	declaredFieldCache.Store(t, names)
	return names
}

// marshalWithExtra encodes declared and merges extra into the same JSON object.
// typeName only appears in error messages.
func marshalWithExtra(declared any, extra map[string]any, t reflect.Type, typeName string) ([]byte, error) {
	encoded, err := json.Marshal(declared)
	if err != nil {
		return nil, err
	}
	if len(extra) == 0 {
		return encoded, nil
	}

	var merged map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &merged); err != nil {
		return nil, err
	}

	names := declaredFieldNames(t)
	for key, value := range extra {
		if _, isDeclared := names[key]; isDeclared {
			return nil, fmt.Errorf("dstack: %s Extra key %q collides with a declared field; set the field instead", typeName, key)
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("dstack: %s Extra key %q: %w", typeName, key, err)
		}
		merged[key] = raw
	}
	return json.Marshal(merged)
}

// unmarshalExtra returns the keys of data that t does not declare.
func unmarshalExtra(data []byte, t reflect.Type, typeName string) (map[string]any, error) {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, err
	}

	names := declaredFieldNames(t)
	extra := make(map[string]any)
	for key, raw := range all {
		if _, isDeclared := names[key]; isDeclared {
			continue
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, fmt.Errorf("dstack: %s field %q: %w", typeName, key, err)
		}
		extra[key] = value
	}
	if len(extra) == 0 {
		return nil, nil
	}
	return extra, nil
}

// MarshalJSON emits the declared fields and then merges Extra into the same
// object.
func (a AppCompose) MarshalJSON() ([]byte, error) {
	type plain AppCompose
	return marshalWithExtra(plain(a), a.Extra, reflect.TypeFor[AppCompose](), "app_compose")
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

	extra, err := unmarshalExtra(data, reflect.TypeFor[AppCompose](), "app_compose")
	if err != nil {
		return err
	}
	a.Extra = extra
	return nil
}

func (r Requirements) MarshalJSON() ([]byte, error) {
	type plain Requirements
	return marshalWithExtra(plain(r), r.Extra, reflect.TypeFor[Requirements](), "requirements")
}

func (r *Requirements) UnmarshalJSON(data []byte) error {
	type plain Requirements
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*r = Requirements(decoded)

	extra, err := unmarshalExtra(data, reflect.TypeFor[Requirements](), "requirements")
	if err != nil {
		return err
	}
	r.Extra = extra
	return nil
}

func (g GpuPolicy) MarshalJSON() ([]byte, error) {
	type plain GpuPolicy
	return marshalWithExtra(plain(g), g.Extra, reflect.TypeFor[GpuPolicy](), "gpu_policy")
}

func (g *GpuPolicy) UnmarshalJSON(data []byte) error {
	type plain GpuPolicy
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*g = GpuPolicy(decoded)

	extra, err := unmarshalExtra(data, reflect.TypeFor[GpuPolicy](), "gpu_policy")
	if err != nil {
		return err
	}
	g.Extra = extra
	return nil
}

func (d DockerConfig) MarshalJSON() ([]byte, error) {
	type plain DockerConfig
	return marshalWithExtra(plain(d), d.Extra, reflect.TypeFor[DockerConfig](), "docker_config")
}

func (d *DockerConfig) UnmarshalJSON(data []byte) error {
	type plain DockerConfig
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*d = DockerConfig(decoded)

	extra, err := unmarshalExtra(data, reflect.TypeFor[DockerConfig](), "docker_config")
	if err != nil {
		return err
	}
	d.Extra = extra
	return nil
}

func (p PortPolicy) MarshalJSON() ([]byte, error) {
	type plain PortPolicy
	return marshalWithExtra(plain(p), p.Extra, reflect.TypeFor[PortPolicy](), "port_policy")
}

func (p *PortPolicy) UnmarshalJSON(data []byte) error {
	type plain PortPolicy
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*p = PortPolicy(decoded)

	extra, err := unmarshalExtra(data, reflect.TypeFor[PortPolicy](), "port_policy")
	if err != nil {
		return err
	}
	p.Extra = extra
	return nil
}

func (p PortAttrs) MarshalJSON() ([]byte, error) {
	type plain PortAttrs
	return marshalWithExtra(plain(p), p.Extra, reflect.TypeFor[PortAttrs](), "port_policy.ports entry")
}

func (p *PortAttrs) UnmarshalJSON(data []byte) error {
	type plain PortAttrs
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*p = PortAttrs(decoded)

	extra, err := unmarshalExtra(data, reflect.TypeFor[PortAttrs](), "port_policy.ports entry")
	if err != nil {
		return err
	}
	p.Extra = extra
	return nil
}

func (v VerityVolume) MarshalJSON() ([]byte, error) {
	type plain VerityVolume
	return marshalWithExtra(plain(v), v.Extra, reflect.TypeFor[VerityVolume](), "verity_volumes entry")
}

func (v *VerityVolume) UnmarshalJSON(data []byte) error {
	type plain VerityVolume
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*v = VerityVolume(decoded)

	extra, err := unmarshalExtra(data, reflect.TypeFor[VerityVolume](), "verity_volumes entry")
	if err != nil {
		return err
	}
	v.Extra = extra
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
