// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-FileCopyrightText: © 2024 Nethermind <contact@nethermind.io>
//
// SPDX-License-Identifier: Apache-2.0

// Provides a dstack SDK client and related utilities
package dstack

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Represents the response from a TLS key derivation request.
type GetTlsKeyResponse struct {
	Key              string   `json:"key"`
	CertificateChain []string `json:"certificate_chain"`
}

// AsUint8Array converts the private key to bytes, optionally limiting the length
func (r *GetTlsKeyResponse) AsUint8Array(maxLength ...int) ([]byte, error) {
	block, _ := pem.Decode([]byte(r.Key))
	if block == nil {
		return nil, fmt.Errorf("failed to decode pem private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	var keyBytes []byte
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		keyBytes = k.D.FillBytes(make([]byte, (k.Curve.Params().N.BitLen()+7)/8))
	case ed25519.PrivateKey:
		keyBytes = k.Seed()
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}

	if len(maxLength) > 0 && maxLength[0] > 0 && maxLength[0] < len(keyBytes) {
		return keyBytes[:maxLength[0]], nil
	}
	return keyBytes, nil
}

// Represents the response from a key derivation request.
type GetKeyResponse struct {
	Key            string   `json:"key"`
	SignatureChain []string `json:"signature_chain"`
}

// DecodeKey returns the key as bytes
func (r *GetKeyResponse) DecodeKey() ([]byte, error) {
	return hex.DecodeString(r.Key)
}

// DecodeSignatureChain returns the signature chain as bytes
func (r *GetKeyResponse) DecodeSignatureChain() ([][]byte, error) {
	result := make([][]byte, len(r.SignatureChain))
	for i, sig := range r.SignatureChain {
		bytes, err := hex.DecodeString(sig)
		if err != nil {
			return nil, fmt.Errorf("failed to decode signature %d: %w", i, err)
		}
		result[i] = bytes
	}
	return result, nil
}

// Represents the response from a quote request.
type GetQuoteResponse struct {
	Quote      string `json:"quote"`
	EventLog   string `json:"event_log"`
	ReportData string `json:"report_data"`
	VmConfig   string `json:"vm_config"`
}

// DecodeQuote returns the quote bytes
func (r *GetQuoteResponse) DecodeQuote() ([]byte, error) {
	return hex.DecodeString(r.Quote)
}

// DecodeReportData returns the report data bytes
func (r *GetQuoteResponse) DecodeReportData() ([]byte, error) {
	return hex.DecodeString(r.ReportData)
}

// DecodeEventLog returns the event log as structured data
func (r *GetQuoteResponse) DecodeEventLog() ([]EventLog, error) {
	var events []EventLog
	err := json.Unmarshal([]byte(r.EventLog), &events)
	return events, err
}

// Represents the response from an attestation request.
type AttestResponse struct {
	Attestation []byte
}

// GpuInfoResponse contains GPU information collected during boot.
type GpuInfoResponse struct {
	Attestation string `json:"attestation"`
}

// AttestGpuResponse is the result of a fresh, on-demand NVIDIA GPU attestation.
//
// It proves that a genuine NVIDIA GPU reachable from this CVM signed the nonce,
// right now. It does NOT prove the GPU is attached to this CVM: an NVIDIA report
// binds the device and the nonce, nothing more, so a hostile host can relay the
// challenge to a real GPU elsewhere. Sound as a local health check, unsound as
// evidence to a remote party -- for that, use the boot-time `gpu-attestation`
// event bound to the quote.
type AttestGpuResponse struct {
	// Evidence is the complete nvattest JSON for the requested nonce.
	Evidence string `json:"evidence"`
	// Nonce is the nonce the GPU answered, hex-encoded, as it appears in eat_nonce.
	Nonce string `json:"nonce"`
}

// Represents an event log entry in the TCB info
type EventLog struct {
	IMR          int    `json:"imr"`
	EventType    int    `json:"event_type"`
	Digest       string `json:"digest"`
	Event        string `json:"event"`
	EventPayload string `json:"event_payload"`
	// Runtime event log version. The field is omitted from the wire format for
	// version 1, so a zero value means V1 rather than "unset"; treat 0 and 1
	// alike. Only dstack runtime events carry a version.
	Version int `json:"version,omitempty"`
	// Hex-encoded digest pre-image, present on V2 runtime events. When set,
	// sha384(hex_decode(Preimage)) equals Digest.
	Preimage string `json:"preimage,omitempty"`
}

// Represents the TCB information
type TcbInfo struct {
	Mrtd       string     `json:"mrtd"`
	Rtmr0      string     `json:"rtmr0"`
	Rtmr1      string     `json:"rtmr1"`
	Rtmr2      string     `json:"rtmr2"`
	Rtmr3      string     `json:"rtmr3"`
	AppCompose string     `json:"app_compose"`
	EventLog   []EventLog `json:"event_log"`
	// V0.3.x fields
	RootfsHash string `json:"rootfs_hash,omitempty"`
	// V0.5.x fields
	MrAggregated string `json:"mr_aggregated,omitempty"`
	OsImageHash  string `json:"os_image_hash,omitempty"`
	ComposeHash  string `json:"compose_hash,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
}

// Represents the response from an info request
type InfoResponse struct {
	AppID           string `json:"app_id"`
	InstanceID      string `json:"instance_id"`
	AppCert         string `json:"app_cert"`
	TcbInfo         string `json:"tcb_info"`
	AppName         string `json:"app_name"`
	DeviceID        string `json:"device_id"`
	MrAggregated    string `json:"mr_aggregated,omitempty"`
	KeyProviderInfo string `json:"key_provider_info"`
	// Optional: empty if OS image is not measured by KMS
	OsImageHash  string `json:"os_image_hash,omitempty"`
	ComposeHash  string `json:"compose_hash"`
	VmConfig     string `json:"vm_config,omitempty"`
	CloudVendor  string `json:"cloud_vendor,omitempty"`
	CloudProduct string `json:"cloud_product,omitempty"`
}

// DecodeTcbInfo decodes the TcbInfo string into a TcbInfo struct
func (r *InfoResponse) DecodeTcbInfo() (*TcbInfo, error) {
	if r.TcbInfo == "" {
		return nil, fmt.Errorf("tcb_info is empty")
	}

	var tcbInfo TcbInfo
	err := json.Unmarshal([]byte(r.TcbInfo), &tcbInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tcb_info: %w", err)
	}

	return &tcbInfo, nil
}

// QuoteHashAlgorithm represents the hash algorithm used for quote generation
type QuoteHashAlgorithm string

const (
	// SHA512 hash algorithm
	SHA512 QuoteHashAlgorithm = "sha512"
	// RAW means no hashing, just use the raw bytes
	RAW QuoteHashAlgorithm = "raw"
)

// Handles communication with the dstack service.
type DstackClient struct {
	endpoint   string
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
}

// Functional option for configuring a DstackClient.
type DstackClientOption func(*DstackClient)

// Sets the endpoint for the DstackClient.
func WithEndpoint(endpoint string) DstackClientOption {
	return func(c *DstackClient) {
		c.endpoint = endpoint
	}
}

// Sets the logger for the DstackClient
func WithLogger(logger *slog.Logger) DstackClientOption {
	return func(c *DstackClient) {
		c.logger = logger
	}
}

// Creates a new DstackClient instance based on the provided endpoint.
// If the endpoint is empty, it will use the simulator endpoint if it is
// set in the environment through DSTACK_SIMULATOR_ENDPOINT. Otherwise, it
// will use the default endpoint at /var/run/dstack.sock.
func NewDstackClient(opts ...DstackClientOption) *DstackClient {
	client := &DstackClient{
		endpoint:   "",
		baseURL:    "",
		httpClient: &http.Client{},
		logger:     slog.Default(),
	}

	for _, opt := range opts {
		opt(client)
	}

	client.endpoint = client.getEndpoint()

	if strings.HasPrefix(client.endpoint, "http://") || strings.HasPrefix(client.endpoint, "https://") {
		client.baseURL = client.endpoint
	} else {
		client.baseURL = "http://localhost"
		client.httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", client.endpoint)
				},
			},
		}
	}

	return client
}

// Returns the appropriate endpoint based on environment and input. If the
// endpoint is empty, it will use the simulator endpoint if it is set in the
// environment through DSTACK_SIMULATOR_ENDPOINT. Otherwise, it will try
// /var/run/dstack/dstack.sock first, falling back to /var/run/dstack.sock
// for backward compatibility.
func (c *DstackClient) getEndpoint() string {
	if c.endpoint != "" {
		return c.endpoint
	}
	if simEndpoint, exists := os.LookupEnv("DSTACK_SIMULATOR_ENDPOINT"); exists {
		c.logger.Info("using simulator endpoint", "endpoint", simEndpoint)
		return simEndpoint
	}
	// Try paths in order: legacy paths first, then namespaced paths
	socketPaths := []string{
		"/var/run/dstack.sock",
		"/run/dstack.sock",
		"/var/run/dstack/dstack.sock",
		"/run/dstack/dstack.sock",
	}
	for _, path := range socketPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	// Default to new path even if not exists (will fail with clear error)
	return socketPaths[0]
}

// Sends an RPC request to the dstack service.
func (c *DstackClient) sendRPCRequest(ctx context.Context, path string, payload interface{}) ([]byte, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+path, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dstack-sdk-go/0.1.0")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// TlsKeyOption defines a function type for TLS key options
type TlsKeyOption func(*tlsKeyOptions)

// tlsKeyOptions holds all the optional parameters for GetTlsKey
type tlsKeyOptions struct {
	subject         string
	altNames        []string
	usageRaTls      bool
	usageServerAuth bool
	usageClientAuth bool
	notBefore       *uint64
	notAfter        *uint64
	withAppInfo     *bool
}

// WithSubject sets the subject for the TLS key
func WithSubject(subject string) TlsKeyOption {
	return func(opts *tlsKeyOptions) {
		opts.subject = subject
	}
}

// WithAltNames sets the alternative names for the TLS key
func WithAltNames(altNames []string) TlsKeyOption {
	return func(opts *tlsKeyOptions) {
		opts.altNames = altNames
	}
}

// WithUsageRaTls sets the RA TLS usage flag
func WithUsageRaTls(usage bool) TlsKeyOption {
	return func(opts *tlsKeyOptions) {
		opts.usageRaTls = usage
	}
}

// WithUsageServerAuth sets the server auth usage flag
func WithUsageServerAuth(usage bool) TlsKeyOption {
	return func(opts *tlsKeyOptions) {
		opts.usageServerAuth = usage
	}
}

// WithUsageClientAuth sets the client auth usage flag
func WithUsageClientAuth(usage bool) TlsKeyOption {
	return func(opts *tlsKeyOptions) {
		opts.usageClientAuth = usage
	}
}

// WithNotBefore sets the not_before timestamp for the certificate
func WithNotBefore(t uint64) TlsKeyOption {
	return func(opts *tlsKeyOptions) {
		opts.notBefore = &t
	}
}

// WithNotAfter sets the not_after timestamp for the certificate
func WithNotAfter(t uint64) TlsKeyOption {
	return func(opts *tlsKeyOptions) {
		opts.notAfter = &t
	}
}

// WithAppInfo sets the with_app_info flag for the certificate
func WithAppInfo(enabled bool) TlsKeyOption {
	return func(opts *tlsKeyOptions) {
		opts.withAppInfo = &enabled
	}
}

// Gets a TLS key from the dstack service with optional parameters.
func (c *DstackClient) GetTlsKey(
	ctx context.Context,
	options ...TlsKeyOption,
) (*GetTlsKeyResponse, error) {
	// Default options
	opts := &tlsKeyOptions{}

	// Apply provided options
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

	data, err := c.sendRPCRequest(ctx, "/GetTlsKey", payload)
	if err != nil {
		return nil, err
	}

	var response GetTlsKeyResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// requiresVersionCheck returns true for algorithms that need OS >= 0.5.7.
func requiresVersionCheck(algorithm string) bool {
	switch algorithm {
	case "secp256k1", "k256", "":
		return false
	default:
		return true
	}
}

// ensureAlgorithmSupported checks the OS version when a non-secp256k1 algorithm is requested.
// On old OS (no Version RPC), it returns an error to prevent silent key type mismatch.
func (c *DstackClient) ensureAlgorithmSupported(ctx context.Context, algorithm string) error {
	if !requiresVersionCheck(algorithm) {
		return nil
	}
	if _, err := c.GetVersion(ctx); err != nil {
		return fmt.Errorf("algorithm %q is not supported: OS version too old (Version RPC unavailable)", algorithm)
	}
	return nil
}

// Gets a key from the dstack service.
func (c *DstackClient) GetKey(ctx context.Context, path string, purpose string, algorithm string) (*GetKeyResponse, error) {
	if err := c.ensureAlgorithmSupported(ctx, algorithm); err != nil {
		return nil, err
	}
	payload := map[string]interface{}{
		"path":      path,
		"purpose":   purpose,
		"algorithm": algorithm,
	}

	data, err := c.sendRPCRequest(ctx, "/GetKey", payload)
	if err != nil {
		return nil, err
	}

	var response GetKeyResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// Gets a TDX quote from the dstack service. Needs Intel TDX: on a platform
// without it the guest agent returns an error, and on GCP Confidential VMs it
// answers with the TDX quote alone, leaving out the vTPM quote GCP's
// verification also binds. Attest should be used in both cases.
func (c *DstackClient) GetQuote(ctx context.Context, reportData []byte) (*GetQuoteResponse, error) {
	if len(reportData) > 64 {
		return nil, fmt.Errorf("report data is too large, it should be at most 64 bytes")
	}

	payload := map[string]interface{}{
		"report_data": hex.EncodeToString(reportData),
	}

	data, err := c.sendRPCRequest(ctx, "/GetQuote", payload)
	if err != nil {
		return nil, err
	}

	var response GetQuoteResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// Gets a versioned attestation from the dstack service.
func (c *DstackClient) Attest(ctx context.Context, reportData []byte) (*AttestResponse, error) {
	if len(reportData) > 64 {
		return nil, fmt.Errorf("report data is too large, it should be at most 64 bytes")
	}

	payload := map[string]interface{}{
		"report_data": hex.EncodeToString(reportData),
	}

	data, err := c.sendRPCRequest(ctx, "/Attest", payload)
	if err != nil {
		return nil, err
	}

	var response struct {
		Attestation string `json:"attestation"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	attestation, err := hex.DecodeString(response.Attestation)
	if err != nil {
		return nil, err
	}

	return &AttestResponse{Attestation: attestation}, nil
}

// AttestGpu runs NVIDIA GPU attestation now, against a 32-byte nonce you choose.
//
// See AttestGpuResponse for what this does and does not prove.
func (c *DstackClient) AttestGpu(ctx context.Context, nonce []byte) (*AttestGpuResponse, error) {
	if len(nonce) != 32 {
		return nil, fmt.Errorf("nonce must be exactly 32 bytes, got %d", len(nonce))
	}

	payload := map[string]interface{}{"nonce": hex.EncodeToString(nonce)}
	data, err := c.sendRPCRequest(ctx, "/AttestGpu", payload)
	if err != nil {
		return nil, err
	}

	var response AttestGpuResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// GpuInfo returns GPU information collected during boot.
func (c *DstackClient) GpuInfo(ctx context.Context) (*GpuInfoResponse, error) {
	data, err := c.sendRPCRequest(ctx, "/GpuInfo", map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	var response GpuInfoResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// Represents the response from a Version request.
type VersionResponse struct {
	Version string `json:"version"`
	Rev     string `json:"rev"`
}

// Gets the guest-agent version.
//
// Returns the version on OS >= 0.5.7.
// Returns an error on older OS versions that lack the Version RPC.
func (c *DstackClient) GetVersion(ctx context.Context) (*VersionResponse, error) {
	data, err := c.sendRPCRequest(ctx, "/Version", map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	var response VersionResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// Sends a request to get information about the CVM instance
func (c *DstackClient) Info(ctx context.Context) (*InfoResponse, error) {
	data, err := c.sendRPCRequest(ctx, "/Info", map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	var response InfoResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

type SignResponse struct {
	Signature      []byte
	SignatureChain [][]byte
	PublicKey      []byte
}

// Signs a payload.
func (c *DstackClient) Sign(ctx context.Context, algorithm string, data []byte) (*SignResponse, error) {
	payload := map[string]interface{}{
		"algorithm": algorithm,
		"data":      hex.EncodeToString(data),
	}

	respData, err := c.sendRPCRequest(ctx, "/Sign", payload)
	if err != nil {
		return nil, err
	}

	var response struct {
		Signature      string   `json:"signature"`
		SignatureChain []string `json:"signature_chain"`
		PublicKey      string   `json:"public_key"`
	}
	if err := json.Unmarshal(respData, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal sign response: %w", err)
	}

	sig, err := hex.DecodeString(response.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	pubKey, err := hex.DecodeString(response.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	sigChain := make([][]byte, len(response.SignatureChain))
	for i, s := range response.SignatureChain {
		sigChain[i], err = hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("failed to decode signature chain element %d: %w", i, err)
		}
	}

	return &SignResponse{
		Signature:      sig,
		SignatureChain: sigChain,
		PublicKey:      pubKey,
	}, nil
}

// IsReachable checks if the service is reachable
func (c *DstackClient) IsReachable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	_, err := c.Info(ctx)
	return err == nil
}

// Legacy methods for backward compatibility with warnings

// DeriveKey is deprecated. Use GetKey instead.
// Deprecated: Use GetKey instead.
func (c *DstackClient) DeriveKey(path string, subject string, altNames []string) (*GetTlsKeyResponse, error) {
	return nil, fmt.Errorf("deriveKey is deprecated, please use GetKey instead")
}

// TdxQuote is deprecated. Use GetQuote instead.
// Deprecated: Use GetQuote instead.
func (c *DstackClient) TdxQuote(ctx context.Context, reportData []byte, hashAlgorithm string) (*GetQuoteResponse, error) {
	c.logger.Warn("tdxQuote is deprecated, please use GetQuote instead")
	if hashAlgorithm != "raw" {
		return nil, fmt.Errorf("tdxQuote only supports raw hash algorithm")
	}
	return c.GetQuote(ctx, reportData)
}

// TappdClient is a deprecated wrapper around DstackClient for backward compatibility.
// Deprecated: Use DstackClient instead.
type TappdClient struct {
	*DstackClient
}

// NewTappdClient creates a new deprecated TappdClient.
// Deprecated: Use NewDstackClient instead.
func NewTappdClient(opts ...DstackClientOption) *TappdClient {
	// Create a modified option to use TAPPD_SIMULATOR_ENDPOINT
	tappdOpts := make([]DstackClientOption, 0, len(opts)+1)

	// Add default endpoint option that checks TAPPD_SIMULATOR_ENDPOINT
	tappdOpts = append(tappdOpts, func(c *DstackClient) {
		if c.endpoint == "" {
			if simEndpoint, exists := os.LookupEnv("TAPPD_SIMULATOR_ENDPOINT"); exists {
				c.logger.Warn("Using tappd endpoint", "endpoint", simEndpoint)
				c.endpoint = simEndpoint
			} else {
				c.endpoint = "/var/run/tappd.sock"
			}
		}
	})

	// Add user-provided options
	tappdOpts = append(tappdOpts, opts...)

	client := NewDstackClient(tappdOpts...)
	client.logger.Warn("TappdClient is deprecated, please use DstackClient instead")

	return &TappdClient{
		DstackClient: client,
	}
}

// Override deprecated methods to use proper tappd RPC paths

// DeriveKey is deprecated. Use GetKey instead.
// Deprecated: Use GetKey instead.
func (tc *TappdClient) DeriveKey(ctx context.Context, path string, subject string, altNames []string) (*GetTlsKeyResponse, error) {
	tc.logger.Warn("deriveKey is deprecated, please use GetKey instead")

	if subject == "" {
		subject = path
	}

	payload := map[string]interface{}{
		"path":    path,
		"subject": subject,
	}
	if len(altNames) > 0 {
		payload["alt_names"] = altNames
	}

	data, err := tc.sendRPCRequest(ctx, "/prpc/Tappd.DeriveKey", payload)
	if err != nil {
		return nil, err
	}

	var response GetTlsKeyResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// TdxQuote is deprecated. Use GetQuote instead.
// Deprecated: Use GetQuote instead.
func (tc *TappdClient) TdxQuote(ctx context.Context, reportData []byte, hashAlgorithm string) (*GetQuoteResponse, error) {
	tc.logger.Warn("tdxQuote is deprecated, please use GetQuote instead")

	if hashAlgorithm == "raw" {
		if len(reportData) > 64 {
			return nil, fmt.Errorf("report data is too large, it should be at most 64 bytes when hashAlgorithm is raw")
		}
		if len(reportData) < 64 {
			// Left-pad with zeros
			padding := make([]byte, 64-len(reportData))
			reportData = append(padding, reportData...)
		}
	}

	payload := map[string]interface{}{
		"report_data":    hex.EncodeToString(reportData),
		"hash_algorithm": hashAlgorithm,
	}

	data, err := tc.sendRPCRequest(ctx, "/prpc/Tappd.TdxQuote", payload)
	if err != nil {
		return nil, err
	}

	var response GetQuoteResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return &response, nil
}
