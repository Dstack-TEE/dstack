// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-FileCopyrightText: © 2024 Nethermind <contact@nethermind.io>
//
// SPDX-License-Identifier: Apache-2.0

// Provides a dstack SDK client and related utilities
package dstack

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
)

// Represents the response from a TLS key derivation request.
type GetTlsKeyResponse struct {
	Key              string   `json:"key"`
	CertificateChain []string `json:"certificate_chain"`
}

// Represents the response from a key derivation request.
type GetKeyResponse struct {
	Key            string   `json:"key"`
	SignatureChain []string `json:"signature_chain"`
}

// Represents the response from a quote request.
type GetQuoteResponse struct {
	Quote      []byte `json:"quote"`
	EventLog   string `json:"event_log"`
	ReportData []byte `json:"report_data"`
	VmConfig   string `json:"vm_config"`
}

// Represents the response from an attestation request.
type AttestResponse struct {
	Attestation []byte
}

// Represents an event log entry in the TCB info
type EventLog struct {
	IMR          int    `json:"imr"`
	EventType    int    `json:"event_type"`
	Digest       string `json:"digest"`
	Event        string `json:"event"`
	EventPayload string `json:"event_payload"`
}

// Represents the TCB information
type TcbInfo struct {
	Mrtd  string `json:"mrtd"`
	Rtmr0 string `json:"rtmr0"`
	Rtmr1 string `json:"rtmr1"`
	Rtmr2 string `json:"rtmr2"`
	Rtmr3 string `json:"rtmr3"`
	// The hash of the OS image. This is empty if the OS image is not measured by KMS.
	OsImageHash string     `json:"os_image_hash,omitempty"`
	ComposeHash string     `json:"compose_hash"`
	DeviceID    string     `json:"device_id"`
	AppCompose  string     `json:"app_compose"`
	EventLog    []EventLog `json:"event_log"`
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
	OsImageHash string `json:"os_image_hash,omitempty"`
	ComposeHash string `json:"compose_hash"`
	VmConfig    string `json:"vm_config,omitempty"`
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

const INIT_MR = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

// Replays the RTMR history to calculate final RTMR values
func replayRTMR(history []string) (string, error) {
	if len(history) == 0 {
		return INIT_MR, nil
	}

	mr := make([]byte, 48)

	for _, content := range history {
		contentBytes, err := hex.DecodeString(content)
		if err != nil {
			return "", err
		}

		if len(contentBytes) < 48 {
			padding := make([]byte, 48-len(contentBytes))
			contentBytes = append(contentBytes, padding...)
		}

		h := sha512.New384()
		h.Write(append(mr, contentBytes...))
		mr = h.Sum(nil)
	}

	return hex.EncodeToString(mr), nil
}

// Replays the RTMR history to calculate final RTMR values
func (r *GetQuoteResponse) ReplayRTMRs() (map[int]string, error) {
	var eventLog []struct {
		IMR    int    `json:"imr"`
		Digest string `json:"digest"`
	}
	json.Unmarshal([]byte(r.EventLog), &eventLog)

	rtmrs := make(map[int]string, 4)
	for idx := 0; idx < 4; idx++ {
		history := make([]string, 0)
		for _, event := range eventLog {
			if event.IMR == idx {
				history = append(history, event.Digest)
			}
		}

		rtmr, err := replayRTMR(history)
		if err != nil {
			return nil, err
		}

		rtmrs[idx] = rtmr
	}

	return rtmrs, nil
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

// Gets a quote from the dstack service.
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

	var response struct {
		Quote      string `json:"quote"`
		EventLog   string `json:"event_log"`
		ReportData string `json:"report_data"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	quote, err := hex.DecodeString(response.Quote)
	if err != nil {
		return nil, err
	}

	reportDataBytes, err := hex.DecodeString(response.ReportData)
	if err != nil {
		return nil, err
	}

	return &GetQuoteResponse{
		Quote:      quote,
		EventLog:   response.EventLog,
		ReportData: reportDataBytes,
	}, nil
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

type VerifyResponse struct {
	Valid bool `json:"valid"`
}

// Verifies a payload.
func (c *DstackClient) Verify(ctx context.Context, algorithm string, data []byte, signature []byte, publicKey []byte) (*VerifyResponse, error) {
	payload := map[string]interface{}{
		"algorithm":  algorithm,
		"data":       hex.EncodeToString(data),
		"signature":  hex.EncodeToString(signature),
		"public_key": hex.EncodeToString(publicKey),
	}

	respData, err := c.sendRPCRequest(ctx, "/Verify", payload)
	if err != nil {
		return nil, err
	}

	var response VerifyResponse
	if err := json.Unmarshal(respData, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal verify response: %w", err)
	}

	return &response, nil
}

// EmitEvent sends an event to be extended to RTMR3 on TDX platform.
// The event will be extended to RTMR3 with the provided name and payload.
//
// Requires dstack OS 0.5.0 or later.
func (c *DstackClient) EmitEvent(ctx context.Context, event string, payload []byte) error {
	_, err := c.sendRPCRequest(ctx, "/EmitEvent", map[string]interface{}{
		"event":   event,
		"payload": hex.EncodeToString(payload),
	})
	return err
}
