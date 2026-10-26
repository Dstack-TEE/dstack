// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// Client for `dstack.guest.v1`, the versioned guest agent API added in dstack
// 0.6.0 and served at `/v1/<Method>` on the same socket as the frozen v0
// surface.
//
// `docs/guest-api-v1.md` is the normative specification; this file is a
// transport mirror of it and nothing more. It does not paper over differences
// between the two surfaces, because there is no compatibility to preserve: a v1
// key derived from a given name is not the v0 key of that name.

package dstack

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Response from a v1 certificate issuance request.
type IssueCertV1Response struct {
	// The private key the agent generated for this certificate, PEM-encoded.
	// Freshly generated per call and not derived from the app identity.
	Key string `json:"key"`
	// The certificate chain, leaf first, each entry PEM-encoded.
	CertificateChain []string `json:"certificate_chain"`
}

// Response from a v1 key derivation request.
type GetKeyV1Response struct {
	// The derived private key: 32 raw bytes for both supported algorithms.
	Key []byte
	// The corresponding public key: SEC1 compressed (33 bytes) for secp256k1,
	// raw (32 bytes) for ed25519. These are the exact bytes the chain's first
	// link commits to.
	PublicKey []byte
	// Two links: [0] the app root key over the v1 key claim, [1] the KMS root
	// key over the app root public key. See `docs/guest-api-v1.md` for the claim
	// encoding and the verification steps.
	SignatureChain [][]byte
}

// Response from a v1 attestation request.
type AttestV1Response struct {
	// The versioned dstack attestation.
	Attestation []byte
	// The GPU evidence nvattest recorded at guest boot, in the same bundle
	// shape AttestGpu returns. Empty unless the request asked for it and the
	// guest has boot-time output, so absence is the empty slice rather than a
	// sentinel value.
	//
	// Not bound to reportData: nvattest ran at boot against its own nonce.
	// Bind a bundle by replaying the runtime event log and comparing sha256 of
	// its Evidence against the evidence_sha256 field of the measured
	// `gpu-attestation` event.
	BoottimeGpuEvidence []GpuEvidenceBundle
}

// One vendor's GPU evidence, however it was obtained.
//
// Shared by AttestGpu and AttestV1Response.BoottimeGpuEvidence so a consumer
// writes one parser for both, then dispatches on (Vendor, Format): the two
// sources answer different questions and a verifier for one does not appraise
// the other.
type GpuEvidenceBundle struct {
	// Stable GPU vendor identifier, for example `nvidia`.
	Vendor string
	// Vendor-specific evidence format and version. Known values:
	//   `nvidia-nvattest-collect-evidence-json-v1`  fresh, from AttestGpu
	//   `nvidia-nvattest-boottime-json-v1`          the record written at boot
	Format string
	// Opaque vendor-native evidence bytes, hex-encoded on the wire. Do not
	// assume UTF-8 or JSON.
	//
	// These are the vendor's bytes verbatim, and for the boot-time format that
	// exactness is load-bearing: the binding rule is sha256 over precisely
	// these bytes, compared against evidence_sha256 in the measured
	// `gpu-attestation` event. Parsing and re-serializing the JSON changes key
	// order and whitespace, and so changes the digest.
	Evidence []byte
}

// Response from a v1 on-demand GPU attestation request.
type AttestGpuV1Response struct {
	// Evidence, not a verdict: select a verifier by Vendor and Format, then
	// check the signature, certificate chain, measurements and the nonce
	// embedded in the evidence.
	Bundles []GpuEvidenceBundle
}

// Response from a v1 info request.
//
// Identity and configuration, not attestation. Nothing here is evidence: it
// arrives over a local socket with no quote behind it, so confirm the hashes
// against an attestation before relying on them.
type InfoV1Response struct {
	AppID   []byte
	AppName string
	// sha256 over the exact AppCompose bytes below.
	ComposeHash []byte
	// The app-compose document as deployed, verbatim. Do not parse and
	// re-serialize before hashing: key order and whitespace change the digest.
	AppCompose string
	InstanceID []byte
	// Identifies the host machine, not this instance.
	DeviceID     []byte
	OsImageHash  []byte
	MrAggregated []byte
	// JSON document produced and owned by the VMM.
	VmConfig string
	// JSON document owned by dstack-util.
	KeyProviderInfo string
	CloudVendor     string
	CloudProduct    string
}

// Response from a v1 version request.
type VersionV1Response struct {
	Version string `json:"version"`
	Rev     string `json:"rev"`
}

// Handles communication with `dstack.guest.v1` on the guest agent socket.
//
// The method set is exactly the six the service defines. There is no Sign, no
// Verify, no GetQuote and no EmitEvent: see `docs/guest-api-v1.md` for why each
// is absent and what replaces it.
type DstackClientV1 struct {
	transport
}

// DstackClient is the recommended client, and it is v1: the unsuffixed name
// tracks the current API rather than pinning the surface a caller happened to
// start on. Code that used it for v0 fails to compile after the upgrade,
// because the v1 signatures differ -- which is the point. A silent switch would
// hand back different key material under the same call.
type DstackClient = DstackClientV1

// Creates a new DstackClientV1 instance based on the provided endpoint.
// Endpoint resolution is identical to NewDstackClientV0 -- the two surfaces
// share one socket and differ only in the URL path.
func NewDstackClientV1(opts ...DstackClientOption) *DstackClientV1 {
	return &DstackClientV1{transport: newTransport(opts)}
}

// NewDstackClient creates a client for the current API, which is v1. Use it
// unless you specifically need the frozen v0.5.11 surface, in which case name
// NewDstackClientV0 explicitly.
func NewDstackClient(opts ...DstackClientOption) *DstackClient {
	return NewDstackClientV1(opts...)
}

// decodeHexField decodes one hex-encoded protobuf `bytes` field, naming the
// field so a malformed response says which one was wrong.
func decodeHexField(name string, value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode %s: %w", name, err)
	}
	return decoded, nil
}

// requireHexField decodes a `bytes` field the response is meaningless without.
//
// The pointer is what makes absence visible. Decoding into a `string` turns a
// JSON null, and a key the response never had, into "" -- which hex-decodes to
// empty bytes and returns a nil error, so a caller reads an empty private key
// or an empty app_id as a valid answer. The agent emits every field, so
// absence means the response did not come from a working agent, and the other
// three SDKs all refuse it.
func requireHexField(name string, value *string) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("no %s in response: absent or null", name)
	}
	return decodeHexField(name, *value)
}

// optionalHexField decodes a `bytes` field whose absence is the empty default.
//
// os_image_hash and mr_aggregated are the two: reading a missing key as empty
// keeps a degraded Info readable rather than unparseable, and costs nothing
// because neither field means anything unattested. An explicit null is still a
// malformed value, not an omission -- which is why this takes the raw JSON: a
// *string is nil for both, and the two do not mean the same thing.
func optionalHexField(name string, raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return []byte{}, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, fmt.Errorf("malformed %s in response: expected a hex string, got null", name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("malformed %s in response: %w", name, err)
	}
	return decodeHexField(name, value)
}

// optionalString reads a scalar `string` field, defaulting an absent one.
//
// proto3 has no presence for a scalar string, so absence is the empty default
// -- but a null is a value the agent did not send, and Rust, Python and
// JavaScript all refuse it. Raw rather than *string for the same reason
// optionalHexField is: a pointer is nil for both, and the two differ.
func optionalString(name string, raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", fmt.Errorf("malformed %s in response: expected a string, got null", name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("malformed %s in response: %w", name, err)
	}
	return value, nil
}

// requireString reads a string field the response is meaningless without.
//
// A bundle's vendor and format are what a caller switches on to pick a
// verifier, so a missing one does not degrade the answer -- it routes the
// evidence to no verifier at all.
func requireString(name string, value *string) (string, error) {
	if value == nil {
		return "", fmt.Errorf("missing %s in response", name)
	}
	return *value, nil
}

// decodeBundleList reads a repeated GpuEvidenceBundle field from its raw JSON.
//
// emptyWhenAbsent follows the proto: a missing boottime_gpu_evidence is the
// empty list, a missing bundles is a malformed response. A null is malformed
// either way -- absence is an omission, null is a value, and a caller that
// reads null as "no GPUs" has been told something the agent did not say.
func decodeBundleList(name string, raw json.RawMessage, emptyWhenAbsent bool) ([]gpuEvidenceBundleJSON, error) {
	if len(raw) == 0 {
		if emptyWhenAbsent {
			return []gpuEvidenceBundleJSON{}, nil
		}
		return nil, fmt.Errorf("missing %s in response", name)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, fmt.Errorf("malformed %s in response: expected a list, got null", name)
	}
	var wire []gpuEvidenceBundleJSON
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("malformed %s in response: %w", name, err)
	}
	return wire, nil
}

// rpcError reports the agent's own error message when it arrives with a 200.
//
// The transport already rejects a non-2xx status. This covers the other shape:
// a body that carries an error where the answer should be. Without it the
// fields simply come back absent, and before requireHexField that was
// indistinguishable from success.
func rpcError(data []byte) error {
	var probe struct {
		Error *string `json:"error"`
	}
	// A body that is not an object at all is the caller's decode to complain
	// about, with the field names to say what was missing.
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil
	}
	if probe.Error != nil {
		return fmt.Errorf("%s", *probe.Error)
	}
	return nil
}

// Wire form of GpuEvidenceBundle, identical under `bundles` and under
// `boottime_gpu_evidence`.
type gpuEvidenceBundleJSON struct {
	Vendor   *string `json:"vendor"`
	Format   *string `json:"format"`
	Evidence *string `json:"evidence"`
}

// decodeGpuEvidenceBundles decodes one repeated GpuEvidenceBundle field, naming
// the field so a malformed response says which one was wrong. An absent or
// empty list decodes to an empty slice: absence is not an error.
func decodeGpuEvidenceBundles(name string, wire []gpuEvidenceBundleJSON) ([]GpuEvidenceBundle, error) {
	bundles := make([]GpuEvidenceBundle, len(wire))
	for i, bundle := range wire {
		vendor, err := requireString(fmt.Sprintf("vendor of %s element %d", name, i), bundle.Vendor)
		if err != nil {
			return nil, err
		}
		format, err := requireString(fmt.Sprintf("format of %s element %d", name, i), bundle.Format)
		if err != nil {
			return nil, err
		}
		evidence, err := requireHexField(fmt.Sprintf("evidence of %s element %d", name, i), bundle.Evidence)
		if err != nil {
			return nil, err
		}
		bundles[i] = GpuEvidenceBundle{Vendor: vendor, Format: format, Evidence: evidence}
	}
	return bundles, nil
}

// IssueCertV1Option defines a function type for v1 certificate options.
type IssueCertV1Option func(*issueCertV1Options)

type issueCertV1Options struct {
	subject         string
	altNames        []string
	usageRaTls      bool
	usageServerAuth bool
	usageClientAuth bool
	notBefore       *uint64
	notAfter        *uint64
	withAppInfo     *bool
}

// WithCertSubject sets the subject of the certificate to request.
func WithCertSubject(subject string) IssueCertV1Option {
	return func(o *issueCertV1Options) {
		o.subject = subject
	}
}

// WithCertAltNames sets the DNS alternative names for the certificate.
func WithCertAltNames(altNames []string) IssueCertV1Option {
	return func(o *issueCertV1Options) {
		o.altNames = altNames
	}
}

// WithCertUsageRaTls includes the attestation quote in the certificate (RA-TLS).
func WithCertUsageRaTls(usage bool) IssueCertV1Option {
	return func(o *issueCertV1Options) {
		o.usageRaTls = usage
	}
}

// WithCertUsageServerAuth sets the server auth key usage.
//
// Defaults to true, matching the v1 default in the Rust, Python and JS SDKs;
// pass false to issue a certificate that cannot be used for server auth. The
// frozen v0 GetTlsKey defaults it to false instead, because that is what the
// released 0.5.x SDK sent.
func WithCertUsageServerAuth(usage bool) IssueCertV1Option {
	return func(o *issueCertV1Options) {
		o.usageServerAuth = usage
	}
}

// WithCertUsageClientAuth sets the client auth key usage.
func WithCertUsageClientAuth(usage bool) IssueCertV1Option {
	return func(o *issueCertV1Options) {
		o.usageClientAuth = usage
	}
}

// WithCertNotBefore sets the validity start, seconds since the UNIX epoch.
func WithCertNotBefore(t uint64) IssueCertV1Option {
	return func(o *issueCertV1Options) {
		o.notBefore = &t
	}
}

// WithCertNotAfter sets the validity end, seconds since the UNIX epoch.
func WithCertNotAfter(t uint64) IssueCertV1Option {
	return func(o *issueCertV1Options) {
		o.notAfter = &t
	}
}

// WithCertAppInfo includes app info in the certificate.
func WithCertAppInfo(enabled bool) IssueCertV1Option {
	return func(o *issueCertV1Options) {
		o.withAppInfo = &enabled
	}
}

// IssueCert issues a certificate for this application.
//
// The agent generates a key, builds a CSR, and relays it to the KMS (or to the
// local CA when the app runs without one). The key is fresh on every call and
// is not derived from the app identity -- GetKey is the method that derives a
// stable, attestable key. v0 called this GetTlsKey.
func (c *DstackClientV1) IssueCert(ctx context.Context, options ...IssueCertV1Option) (*IssueCertV1Response, error) {
	// usageServerAuth starts true, matching the v1 default in the Rust, Python
	// and JS SDKs: a certificate that cannot be served with is useless to most
	// callers, and a v1 default that differs per language is a trap. Opt out
	// with WithCertUsageServerAuth(false).
	opts := &issueCertV1Options{usageServerAuth: true}
	for _, option := range options {
		option(opts)
	}

	payload := map[string]interface{}{
		"subject":           opts.subject,
		"usage_ra_tls":      opts.usageRaTls,
		"usage_server_auth": opts.usageServerAuth,
		"usage_client_auth": opts.usageClientAuth,
	}
	if len(opts.altNames) > 0 {
		payload["alt_names"] = opts.altNames
	}
	if opts.notBefore != nil {
		payload["not_before"] = *opts.notBefore
	}
	if opts.notAfter != nil {
		payload["not_after"] = *opts.notAfter
	}
	if opts.withAppInfo != nil {
		payload["with_app_info"] = *opts.withAppInfo
	}

	data, err := c.sendRPCRequest(ctx, "/v1/IssueCert", payload)
	if err != nil {
		return nil, err
	}
	if err := rpcError(data); err != nil {
		return nil, err
	}

	var response IssueCertV1Response
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// GetKey derives an application key from (domain, algorithm) and returns it
// with its signature chain.
//
// algorithm is `secp256k1` or `ed25519`, and is required: v1 has no default and
// no `k256` alias, because a typo that silently yields a key of another type
// under a name the caller thought meant something else is worse than an error.
//
// Derivation is flat -- `a/b` is not a child of `a` -- and binds both arguments,
// so these keys differ from the v0 keys of the same name.
func (c *DstackClientV1) GetKey(ctx context.Context, domain string, algorithm string) (*GetKeyV1Response, error) {
	if algorithm == "" {
		return nil, fmt.Errorf("algorithm is required, use `secp256k1` or `ed25519`")
	}

	payload := map[string]interface{}{
		"domain":    domain,
		"algorithm": algorithm,
	}

	data, err := c.sendRPCRequest(ctx, "/v1/GetKey", payload)
	if err != nil {
		return nil, err
	}

	if err := rpcError(data); err != nil {
		return nil, err
	}

	var response struct {
		Key            *string    `json:"key"`
		PublicKey      *string    `json:"public_key"`
		SignatureChain *[]*string `json:"signature_chain"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	key, err := requireHexField("key", response.Key)
	if err != nil {
		return nil, err
	}
	publicKey, err := requireHexField("public_key", response.PublicKey)
	if err != nil {
		return nil, err
	}
	if response.SignatureChain == nil {
		return nil, fmt.Errorf("no signature_chain in response: absent or null")
	}

	chain := make([][]byte, len(*response.SignatureChain))
	for i, link := range *response.SignatureChain {
		chain[i], err = requireHexField(fmt.Sprintf("signature chain element %d", i), link)
		if err != nil {
			return nil, err
		}
	}

	return &GetKeyV1Response{Key: key, PublicKey: publicKey, SignatureChain: chain}, nil
}

// Attest produces a versioned attestation over reportData, which must be
// between 1 and 64 bytes and is zero-padded on the right to 64.
//
// The sole CVM attestation entry point in v1: the attestation already carries
// the TDX quote and the event log, so there is no separate GetQuote.
//
// includeBoottimeGpuEvidence also returns the boot-time nvattest output, as
// GpuEvidenceBundle values -- the same shape AttestGpu returns, so one parser
// serves both. That evidence is not bound to reportData; see AttestV1Response.
func (c *DstackClientV1) Attest(ctx context.Context, reportData []byte, includeBoottimeGpuEvidence bool) (*AttestV1Response, error) {
	if len(reportData) == 0 || len(reportData) > 64 {
		return nil, fmt.Errorf("report data must be between 1 and 64 bytes, got %d", len(reportData))
	}

	payload := map[string]interface{}{
		"report_data":                   hex.EncodeToString(reportData),
		"include_boottime_gpu_evidence": includeBoottimeGpuEvidence,
	}

	data, err := c.sendRPCRequest(ctx, "/v1/Attest", payload)
	if err != nil {
		return nil, err
	}

	if err := rpcError(data); err != nil {
		return nil, err
	}

	var response struct {
		Attestation *string `json:"attestation"`
		// Raw, because a pointer cannot tell an absent field from an explicit
		// null and the two differ here: absence is the empty list, since the
		// field is only populated when the request asked for it, while a null
		// is a malformed value. Rust draws the same line with
		// `#[serde(default)]`, which fills a missing key and rejects a null.
		BoottimeGpuEvidence json.RawMessage `json:"boottime_gpu_evidence"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	attestation, err := requireHexField("attestation", response.Attestation)
	if err != nil {
		return nil, err
	}

	wire, err := decodeBundleList("boottime_gpu_evidence", response.BoottimeGpuEvidence, true)
	if err != nil {
		return nil, err
	}
	boottimeGpuEvidence, err := decodeGpuEvidenceBundles("boottime_gpu_evidence", wire)
	if err != nil {
		return nil, err
	}

	return &AttestV1Response{
		Attestation:         attestation,
		BoottimeGpuEvidence: boottimeGpuEvidence,
	}, nil
}

// AttestGpu collects GPU attestation evidence now, against a nonce the caller
// chooses.
//
// The nonce must be exactly 32 bytes: SPDM fixes the evidence nonce at that
// length and dstack passes it through verbatim, so these bytes can be compared
// directly against the eat_nonce claim. Hash a longer challenge yourself.
//
// This answers "is the device I can talk to right now a genuine CC-enabled
// GPU that signs my challenge". It still does not bind the GPU to this TD.
func (c *DstackClientV1) AttestGpu(ctx context.Context, nonce []byte) (*AttestGpuV1Response, error) {
	if len(nonce) != 32 {
		return nil, fmt.Errorf("nonce must be exactly 32 bytes, got %d", len(nonce))
	}

	payload := map[string]interface{}{"nonce": hex.EncodeToString(nonce)}
	data, err := c.sendRPCRequest(ctx, "/v1/AttestGpu", payload)
	if err != nil {
		return nil, err
	}

	if err := rpcError(data); err != nil {
		return nil, err
	}

	var response struct {
		Bundles json.RawMessage `json:"bundles"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	// Required, unlike boottime_gpu_evidence: bundles is the whole answer of
	// this call, so an absent one is a malformed response rather than a host
	// with no GPUs.
	wire, err := decodeBundleList("bundles", response.Bundles, false)
	if err != nil {
		return nil, err
	}
	bundles, err := decodeGpuEvidenceBundles("bundles", wire)
	if err != nil {
		return nil, err
	}

	return &AttestGpuV1Response{Bundles: bundles}, nil
}

// Info returns this application's identity and configuration.
//
// Flat, unlike v0: there is no tcb_info blob and no app_cert. The measurement
// registers and the event log live on the attestation Attest returns, which is
// the only place they are quote-backed.
func (c *DstackClientV1) Info(ctx context.Context) (*InfoV1Response, error) {
	data, err := c.sendRPCRequest(ctx, "/v1/Info", map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	if err := rpcError(data); err != nil {
		return nil, err
	}

	var response struct {
		AppID           *string         `json:"app_id"`
		AppName         json.RawMessage `json:"app_name"`
		ComposeHash     *string         `json:"compose_hash"`
		AppCompose      json.RawMessage `json:"app_compose"`
		InstanceID      *string         `json:"instance_id"`
		DeviceID        *string         `json:"device_id"`
		OsImageHash     json.RawMessage `json:"os_image_hash"`
		MrAggregated    json.RawMessage `json:"mr_aggregated"`
		VmConfig        json.RawMessage `json:"vm_config"`
		KeyProviderInfo json.RawMessage `json:"key_provider_info"`
		CloudVendor     json.RawMessage `json:"cloud_vendor"`
		CloudProduct    json.RawMessage `json:"cloud_product"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	info := &InfoV1Response{}
	for _, field := range []struct {
		name string
		raw  json.RawMessage
		into *string
	}{
		{"app_name", response.AppName, &info.AppName},
		{"app_compose", response.AppCompose, &info.AppCompose},
		{"vm_config", response.VmConfig, &info.VmConfig},
		{"key_provider_info", response.KeyProviderInfo, &info.KeyProviderInfo},
		{"cloud_vendor", response.CloudVendor, &info.CloudVendor},
		{"cloud_product", response.CloudProduct, &info.CloudProduct},
	} {
		value, err := optionalString(field.name, field.raw)
		if err != nil {
			return nil, err
		}
		*field.into = value
	}

	// app_id, compose_hash, instance_id and device_id are what Info exists to
	// answer, so absence is a malformed response. os_image_hash and
	// mr_aggregated are read as empty when absent, which keeps a degraded Info
	// readable and costs nothing, because neither means anything unattested.
	for _, field := range []struct {
		name  string
		value *string
		into  *[]byte
	}{
		{"app_id", response.AppID, &info.AppID},
		{"compose_hash", response.ComposeHash, &info.ComposeHash},
		{"instance_id", response.InstanceID, &info.InstanceID},
		{"device_id", response.DeviceID, &info.DeviceID},
	} {
		decoded, err := requireHexField(field.name, field.value)
		if err != nil {
			return nil, err
		}
		*field.into = decoded
	}

	for _, field := range []struct {
		name string
		raw  json.RawMessage
		into *[]byte
	}{
		{"os_image_hash", response.OsImageHash, &info.OsImageHash},
		{"mr_aggregated", response.MrAggregated, &info.MrAggregated},
	} {
		decoded, err := optionalHexField(field.name, field.raw)
		if err != nil {
			return nil, err
		}
		*field.into = decoded
	}

	return info, nil
}

// Version returns the guest agent version.
//
// The cheapest probe for whether an agent speaks v1 at all: it takes no
// arguments and touches nothing. An agent that predates v1 has no `/v1` mount
// and answers with a plain HTTP 404.
func (c *DstackClientV1) Version(ctx context.Context) (*VersionV1Response, error) {
	data, err := c.sendRPCRequest(ctx, "/v1/Version", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	if err := rpcError(data); err != nil {
		return nil, err
	}

	var response VersionV1Response
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return &response, nil
}
