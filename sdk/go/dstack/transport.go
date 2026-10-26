// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// Endpoint resolution and JSON-over-prpc plumbing shared by both API versions.
//
// The guest agent serves the frozen v0.5.11 surface and `dstack.guest.v1` on the
// same unix socket, chosen by URL path alone. So the two clients differ only in
// the prefix they post to, and everything below that -- endpoint resolution,
// dialing, error shape -- is one implementation both embed.

package dstack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"unicode/utf8"
)

// sdkVersion is reported in the User-Agent so an agent-side log can tell which
// SDK release a request came from.
const sdkVersion = "0.6.0"

// clientOptions holds what a caller may set at construction.
//
// Every constructor -- NewDstackClient, NewDstackClientV1 and NewDstackClientV0
// -- takes the same options, so a caller moving between surfaces changes the
// constructor and nothing else.
type clientOptions struct {
	endpoint string
	logger   *slog.Logger
}

// Functional option for configuring a dstack client.
type DstackClientOption func(*clientOptions)

// Sets the endpoint for the client.
func WithEndpoint(endpoint string) DstackClientOption {
	return func(o *clientOptions) {
		o.endpoint = endpoint
	}
}

// Sets the logger for the client.
func WithLogger(logger *slog.Logger) DstackClientOption {
	return func(o *clientOptions) {
		o.logger = logger
	}
}

// transport carries the resolved endpoint and the HTTP plumbing.
type transport struct {
	endpoint   string
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
}

// newTransport resolves the options into a ready-to-use transport.
func newTransport(opts []DstackClientOption) transport {
	settings := &clientOptions{logger: slog.Default()}
	for _, opt := range opts {
		opt(settings)
	}

	t := transport{
		endpoint:   settings.endpoint,
		httpClient: &http.Client{},
		logger:     settings.logger,
	}
	t.endpoint = t.getEndpoint()

	if strings.HasPrefix(t.endpoint, "http://") || strings.HasPrefix(t.endpoint, "https://") {
		t.baseURL = t.endpoint
	} else {
		endpoint := t.endpoint
		t.baseURL = "http://localhost"
		t.httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", endpoint)
				},
			},
		}
	}

	return t
}

// Returns the appropriate endpoint based on environment and input. If the
// endpoint is empty, it will use the simulator endpoint if it is set in the
// environment through DSTACK_SIMULATOR_ENDPOINT. Otherwise, it will try
// /var/run/dstack/dstack.sock first, falling back to /var/run/dstack.sock
// for backward compatibility.
func (t *transport) getEndpoint() string {
	if t.endpoint != "" {
		return t.endpoint
	}
	if simEndpoint, exists := os.LookupEnv("DSTACK_SIMULATOR_ENDPOINT"); exists {
		t.logger.Info("using simulator endpoint", "endpoint", simEndpoint)
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

// How much of a server response an error may quote, in characters.
//
// An agent with no route for the path answers with an HTML page, and pasting a
// whole page into an error helps nobody. Rust uses the same number for the same
// reason (`MAX_ERROR_BODY_CHARS` in the Rust SDK); JS uses 300.
//
// Characters rather than bytes so the bound cannot land inside a multi-byte
// sequence. The byte length that follows from it is larger, which is fine for
// something whose only job is to stop an error message running away.
const maxErrorBodyChars = 512

// How much of a failed response to read before giving up on making sense of it.
//
// Larger than the quote bound because the quote is taken from the `error` field
// *inside* the body, and a body cut off mid-string is no longer JSON -- so
// reading exactly 512 characters would turn every large prpc error into a raw
// truncated blob. 64 KiB covers any error an agent produces while still
// refusing to buffer an unbounded page, which is more than Rust does: it reads
// the whole body and bounds only the message.
const maxErrorBodyRead = 64 * 1024

func truncate(text string) string {
	runes := []rune(text)
	if len(runes) <= maxErrorBodyChars {
		return text
	}
	return string(runes[:maxErrorBodyChars]) + "..."
}

// serverErrorText reports what the server said, as far as it can be made out.
//
// A prpc handler that refuses answers `{"error": "..."}` with a 4xx, and that
// field is the only part worth showing. A request that never reached a handler
// -- a `/v1` call against a pre-0.6 agent -- comes back as an HTML error page
// instead, and then the raw body is the only clue there is.
func serverErrorText(body []byte) string {
	if !utf8.Valid(body) {
		return "(non-utf8 response body)"
	}
	text := strings.TrimSpace(string(body))
	if text == "" {
		return "(empty response body)"
	}
	var probe struct {
		Error *string `json:"error"`
	}
	if err := json.Unmarshal([]byte(text), &probe); err == nil && probe.Error != nil {
		return truncate(*probe.Error)
	}
	return truncate(text)
}

// Sends an RPC request to the dstack service.
func (t *transport) sendRPCRequest(ctx context.Context, path string, payload interface{}) ([]byte, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", t.baseURL+path, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dstack-sdk-go/"+sdkVersion)
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// LimitReader, not ReadAll: the only use for these bytes is an error
		// message, and buffering a whole HTML page to quote 512 characters of
		// it is work with no purpose.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyRead))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, serverErrorText(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}
