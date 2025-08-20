// SPDX-FileCopyrightText: © 2024 Nethermind <dstack@nethermind.io>
// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// Provides a dstack SDK Tappd client and related utilities
//
// Author: Franco Barpp Gomes <franco@nethermind.io>
package tappd

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
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

// Represents the hash algorithm used in TDX quote generation.
type QuoteHashAlgorithm string

const (
	SHA256    QuoteHashAlgorithm = "sha256"
	SHA384    QuoteHashAlgorithm = "sha384"
	SHA512    QuoteHashAlgorithm = "sha512"
	SHA3_256  QuoteHashAlgorithm = "sha3-256"
	SHA3_384  QuoteHashAlgorithm = "sha3-384"
	SHA3_512  QuoteHashAlgorithm = "sha3-512"
	KECCAK256 QuoteHashAlgorithm = "keccak256"
	KECCAK384 QuoteHashAlgorithm = "keccak384"
	KECCAK512 QuoteHashAlgorithm = "keccak512"
	RAW       QuoteHashAlgorithm = "raw"
)

// Represents the response from a key derivation request.
type DeriveKeyResponse struct {
	Key              string   `json:"key"`
	CertificateChain []string `json:"certificate_chain"`
}

// Decodes the key to bytes, optionally truncating to maxLength. If maxLength
// < 0, the key is not truncated.
func (d *DeriveKeyResponse) ToBytes(maxLength int) ([]byte, error) {
	content := d.Key

	content = strings.Replace(content, "-----BEGIN PRIVATE KEY-----", "", 1)
	content = strings.Replace(content, "-----END PRIVATE KEY-----", "", 1)
	content = strings.Replace(content, "\n", "", -1)

	binary, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return nil, err
	}

	if maxLength >= 0 && len(binary) > maxLength {
		return binary[:maxLength], nil
	}
	return binary, nil
}

// Represents the response from a TDX quote request.
type TdxQuoteResponse struct {
	Quote    string `json:"quote"`
	EventLog string `json:"event_log"`
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
	Mrtd     string     `json:"mrtd"`
	Rtmr0    string     `json:"rtmr0"`
	Rtmr1    string     `json:"rtmr1"`
	Rtmr2    string     `json:"rtmr2"`
	Rtmr3    string     `json:"rtmr3"`
	EventLog []EventLog `json:"event_log"`
}

// Represents the response from an info request
type TappdInfoResponse struct {
	AppID      string  `json:"app_id"`
	InstanceID string  `json:"instance_id"`
	AppCert    string  `json:"app_cert"`
	TcbInfo    TcbInfo `json:"tcb_info"`
	AppName    string  `json:"app_name"`
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
func (r *TdxQuoteResponse) ReplayRTMRs() (map[int]string, error) {
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

// Handles communication with the Tappd service.
type TappdClient struct {
	endpoint   string
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
}

// Functional option for configuring a TappdClient.
type TappdClientOption func(*TappdClient)

// Sets the endpoint for the TappdClient.
func WithEndpoint(endpoint string) TappdClientOption {
	return func(c *TappdClient) {
		c.endpoint = endpoint
	}
}

// Sets the logger for the TappdClient
func WithLogger(logger *slog.Logger) TappdClientOption {
	return func(c *TappdClient) {
		c.logger = logger
	}
}

// Creates a new TappdClient instance based on the provided endpoint.
// If the endpoint is empty, it will use the simulator endpoint if it is
// set in the environment through TAPPD_SIMULATOR_ENDPOINT. Otherwise, it
// will try /var/run/tappd.sock first, falling back to other known paths
// for backward compatibility.
func NewTappdClient(opts ...TappdClientOption) *TappdClient {
	client := &TappdClient{
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
// environment through TAPPD_SIMULATOR_ENDPOINT. Otherwise, it will try
// /var/run/tappd.sock first, falling back to other known paths
// for backward compatibility.
func (c *TappdClient) getEndpoint() string {
	if c.endpoint != "" {
		return c.endpoint
	}
	if simEndpoint, exists := os.LookupEnv("TAPPD_SIMULATOR_ENDPOINT"); exists {
		c.logger.Info("using tappd simulator endpoint", "endpoint", simEndpoint)
		return simEndpoint
	}
	// Try paths in order: legacy paths first, then namespaced paths
	socketPaths := []string{
		"/var/run/tappd.sock",
		"/run/tappd.sock",
		"/var/run/dstack/tappd.sock",
		"/run/dstack/tappd.sock",
	}
	for _, path := range socketPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return socketPaths[0]
}

// Sends an RPC request to the Tappd service.
func (c *TappdClient) sendRPCRequest(ctx context.Context, path string, payload interface{}) ([]byte, error) {
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
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// Derives a key from the Tappd service. This wraps
// DeriveKeyWithSubjectAndAltNames using the path as the subject and an empty
// altNames.
func (c *TappdClient) DeriveKey(ctx context.Context, path string) (*DeriveKeyResponse, error) {
	return c.DeriveKeyWithSubjectAndAltNames(ctx, path, path, nil)
}

// Derives a key from the Tappd service. This wraps
// DeriveKeyWithSubjectAndAltNames using an empty altNames.
func (c *TappdClient) DeriveKeyWithSubject(ctx context.Context, path string, subject string) (*DeriveKeyResponse, error) {
	return c.DeriveKeyWithSubjectAndAltNames(ctx, path, subject, nil)
}

// Derives a key from the Tappd service, explicitly setting the subject and
// altNames.
func (c *TappdClient) DeriveKeyWithSubjectAndAltNames(ctx context.Context, path string, subject string, altNames []string) (*DeriveKeyResponse, error) {
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

	data, err := c.sendRPCRequest(ctx, "/prpc/Tappd.DeriveKey", payload)
	if err != nil {
		return nil, err
	}

	var response DeriveKeyResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// Sends a TDX quote request to the Tappd service using SHA512 as the report
// data hash algorithm.
func (c *TappdClient) TdxQuote(ctx context.Context, reportData []byte) (*TdxQuoteResponse, error) {
	return c.TdxQuoteWithHashAlgorithm(ctx, reportData, SHA512)
}

// Sends a TDX quote request to the Tappd service with a specific hash
// report data hash algorithm. If the hash algorithm is RAW, the report data
// must be at most 64 bytes - if it's below that, it will be left-padded with
// zeros.
func (c *TappdClient) TdxQuoteWithHashAlgorithm(ctx context.Context, reportData []byte, hashAlgorithm QuoteHashAlgorithm) (*TdxQuoteResponse, error) {
	if hashAlgorithm == RAW {
		if len(reportData) > 64 {
			return nil, fmt.Errorf("report data is too large, it should be at most 64 bytes when hashAlgorithm is RAW")
		}
		if len(reportData) < 64 {
			reportData = append(make([]byte, 64-len(reportData)), reportData...)
		}
	}

	payload := map[string]interface{}{
		"report_data":    hex.EncodeToString(reportData),
		"hash_algorithm": string(hashAlgorithm),
	}

	data, err := c.sendRPCRequest(ctx, "/prpc/Tappd.TdxQuote", payload)
	if err != nil {
		return nil, err
	}

	var response TdxQuoteResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// Sends a request to get information about the Tappd instance
func (c *TappdClient) Info(ctx context.Context) (*TappdInfoResponse, error) {
	data, err := c.sendRPCRequest(ctx, "/prpc/Tappd.Info", map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	var response struct {
		TcbInfo    string `json:"tcb_info"`
		AppID      string `json:"app_id"`
		InstanceID string `json:"instance_id"`
		AppCert    string `json:"app_cert"`
		AppName    string `json:"app_name"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	var tcbInfo TcbInfo
	if err := json.Unmarshal([]byte(response.TcbInfo), &tcbInfo); err != nil {
		return nil, err
	}

	return &TappdInfoResponse{
		AppID:      response.AppID,
		InstanceID: response.InstanceID,
		AppCert:    response.AppCert,
		TcbInfo:    tcbInfo,
		AppName:    response.AppName,
	}, nil
}
