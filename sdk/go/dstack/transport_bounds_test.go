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

// An agent with no route for the path answers with an HTML page, and pasting a
// whole page into an error helps nobody. Rust caps the quoted body at 512
// characters and JS at 300; Go quoted all of it.
func TestErrorQuotesABoundedSliceOfTheBody(t *testing.T) {
	huge := strings.Repeat("E", 20_000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(huge))
	}))
	defer server.Close()

	c := NewDstackClientV1(WithEndpoint(server.URL))
	_, err := c.Version(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(err.Error()) > 1024 {
		t.Errorf("error message is %d bytes, want it bounded: %.120s...", len(err.Error()), err.Error())
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error lost the status: %q", err.Error())
	}
}

// The reason a prpc handler refused is in the `error` field, and that field is
// the only part worth showing.
func TestErrorPrefersThePrpcErrorField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"algorithm is not supported"}`))
	}))
	defer server.Close()

	c := NewDstackClientV1(WithEndpoint(server.URL))
	_, err := c.Version(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "algorithm is not supported") {
		t.Errorf("error lost the agent's message: %q", err.Error())
	}
	if strings.Contains(err.Error(), `{"error"`) {
		t.Errorf("error quoted the raw JSON rather than the message: %q", err.Error())
	}
}

// A short body is quoted whole -- the cap is a ceiling, not a target.
func TestErrorQuotesAShortBodyWhole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<!DOCTYPE html>404"))
	}))
	defer server.Close()

	c := NewDstackClientV1(WithEndpoint(server.URL))
	_, err := c.Version(context.Background())
	if err == nil || !strings.Contains(err.Error(), "<!DOCTYPE html>404") {
		t.Errorf("want the short body quoted whole, got %q", err)
	}
}

// A large `error` field is still read as the field rather than as a raw blob:
// the body has to survive intact far enough to be JSON before the message can
// be lifted out of it.
func TestErrorPrefersThePrpcErrorFieldEvenWhenItIsLarge(t *testing.T) {
	body := `{"error":"` + strings.Repeat("E", 8_000) + `"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	c := NewDstackClientV1(WithEndpoint(server.URL))
	_, err := c.Version(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), `{"error"`) {
		t.Errorf("quoted the raw JSON rather than the message: %.120s", err.Error())
	}
	if len(err.Error()) > 1024 {
		t.Errorf("error message is %d bytes, want it bounded", len(err.Error()))
	}
}
