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
)

// sdkVersion is reported in the User-Agent so an agent-side log can tell which
// SDK release a request came from.
const sdkVersion = "0.6.0"

// clientOptions holds what a caller may set at construction.
//
// Both NewDstackClientV0 and NewDstackClientV1 take the same options: a caller
// moving to v1 changes the constructor and nothing else.
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
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}
