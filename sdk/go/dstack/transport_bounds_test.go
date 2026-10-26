// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package dstack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestErrorQuotesBoundedServerText(t *testing.T) {
	truncated := strings.Repeat("E", maxErrorBodyChars) + "..."
	tests := []struct {
		name, body, want string
	}{
		{"short body", "<!DOCTYPE html>404", "<!DOCTYPE html>404"},
		{"huge body", strings.Repeat("E", 20_000), truncated},
		{"prpc error", `{"error":"algorithm is not supported"}`, "algorithm is not supported"},
		{"huge prpc error", `{"error":"` + strings.Repeat("E", 8_000) + `"}`, truncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			_, err := NewDstackClientV1(WithEndpoint(server.URL)).Version(context.Background())
			if want := "HTTP 400: " + tt.want; err == nil || err.Error() != want {
				t.Errorf("got %.120v, want %.120s", err, want)
			}
		})
	}
}
