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

// Wire form of GpuEvidenceBundle, identical under `bundles` and under
// `boottime_gpu_evidence`.
type gpuEvidenceBundleJSON struct {
	Vendor   string `json:"vendor"`
	Format   string `json:"format"`
	Evidence string `json:"evidence"`
}

// decodeGpuEvidenceBundles decodes one repeated GpuEvidenceBundle field, naming
// the field so a malformed response says which one was wrong. An absent or
// empty list decodes to an empty slice: absence is not an error.
func decodeGpuEvidenceBundles(name string, wire []gpuEvidenceBundleJSON) ([]GpuEvidenceBundle, error) {
	bundles := make([]GpuEvidenceBundle, len(wire))
	for i, bundle := range wire {
		evidence, err := decodeHexField(fmt.Sprintf("evidence of %s element %d", name, i), bundle.Evidence)
		if err != nil {
			return nil, err
		}
		bundles[i] = GpuEvidenceBundle{Vendor: bundle.Vendor, Format: bundle.Format, Evidence: evidence}
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
	opts := &issueCertV1Options{}
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

	var response struct {
		Key            string   `json:"key"`
		PublicKey      string   `json:"public_key"`
		SignatureChain []string `json:"signature_chain"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	key, err := decodeHexField("key", response.Key)
	if err != nil {
		return nil, err
	}
	publicKey, err := decodeHexField("public_key", response.PublicKey)
	if err != nil {
		return nil, err
	}

	chain := make([][]byte, len(response.SignatureChain))
	for i, link := range response.SignatureChain {
		chain[i], err = decodeHexField(fmt.Sprintf("signature chain element %d", i), link)
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

	var response struct {
		Attestation         string                  `json:"attestation"`
		BoottimeGpuEvidence []gpuEvidenceBundleJSON `json:"boottime_gpu_evidence"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	attestation, err := decodeHexField("attestation", response.Attestation)
	if err != nil {
		return nil, err
	}

	boottimeGpuEvidence, err := decodeGpuEvidenceBundles("boottime_gpu_evidence", response.BoottimeGpuEvidence)
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

	var response struct {
		Bundles []gpuEvidenceBundleJSON `json:"bundles"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	bundles, err := decodeGpuEvidenceBundles("bundles", response.Bundles)
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

	var response struct {
		AppID           string `json:"app_id"`
		AppName         string `json:"app_name"`
		ComposeHash     string `json:"compose_hash"`
		AppCompose      string `json:"app_compose"`
		InstanceID      string `json:"instance_id"`
		DeviceID        string `json:"device_id"`
		OsImageHash     string `json:"os_image_hash"`
		MrAggregated    string `json:"mr_aggregated"`
		VmConfig        string `json:"vm_config"`
		KeyProviderInfo string `json:"key_provider_info"`
		CloudVendor     string `json:"cloud_vendor"`
		CloudProduct    string `json:"cloud_product"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	info := &InfoV1Response{
		AppName:         response.AppName,
		AppCompose:      response.AppCompose,
		VmConfig:        response.VmConfig,
		KeyProviderInfo: response.KeyProviderInfo,
		CloudVendor:     response.CloudVendor,
		CloudProduct:    response.CloudProduct,
	}

	for _, field := range []struct {
		name  string
		value string
		into  *[]byte
	}{
		{"app_id", response.AppID, &info.AppID},
		{"compose_hash", response.ComposeHash, &info.ComposeHash},
		{"instance_id", response.InstanceID, &info.InstanceID},
		{"device_id", response.DeviceID, &info.DeviceID},
		{"os_image_hash", response.OsImageHash, &info.OsImageHash},
		{"mr_aggregated", response.MrAggregated, &info.MrAggregated},
	} {
		decoded, err := decodeHexField(field.name, field.value)
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

	var response VersionV1Response
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return &response, nil
}
