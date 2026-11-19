// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package ratls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"testing"

	dcap "github.com/Phala-Network/dcap-qvl/golang-bindings"
)

func TestBootEventLookup(t *testing.T) {
	result := VerifyResult{RuntimeEvents: []RuntimeEvent{{Event: "compose-hash", Payload: []byte("boot")}, {Event: "system-ready"}, {Event: "compose-hash", Payload: []byte("fake")}, {Event: "late-only", Payload: []byte("fake")}}}
	value, ok := result.BootEvent("compose-hash")
	if !ok || string(value) != "boot" {
		t.Fatalf("got %q %v", value, ok)
	}
	if _, ok := result.BootEvent("late-only"); ok {
		t.Fatal("accepted an app event")
	}
	if _, ok := result.BootEvent("system-ready"); ok {
		t.Fatal("accepted the boundary event")
	}
}

func TestBootEventsLookup(t *testing.T) {
	result := VerifyResult{RuntimeEvents: []RuntimeEvent{
		{Event: "init-script-hash", Payload: []byte("first")},
		{Event: "init-script-hash", Payload: []byte("second")},
		{Event: "system-ready"},
		{Event: "init-script-hash", Payload: []byte("injected")},
	}}
	values := result.BootEvents("init-script-hash")
	if len(values) != 2 || string(values[0]) != "first" || string(values[1]) != "second" {
		t.Fatalf("unexpected boot events: %q", values)
	}
}

func readCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("invalid PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// Parse the real quote without fetching collateral; this test covers what
// VerifyCert authenticates after the quote verifier has accepted it.
func parseFixtureQuote(raw []byte, _ string) (*dcap.VerifiedReport, *dcap.Quote, error) {
	quote, err := dcap.ParseQuote(raw)
	return &dcap.VerifiedReport{}, quote, err
}

func TestVerifyCertOffline(t *testing.T) {
	// Both certificates were issued by the same deployment.
	const composeHash = "53226fcd7b6bc7ea979b0a550bf49cad993f28e2370169a9510e56c90b3029dc"
	for _, path := range []string{"tdx-lite-v1-issue-cert.pem", "tdx-lite-v0-get-tls-key.pem"} {
		t.Run(path, func(t *testing.T) {
			cert := readCertificate(t, path)
			result, err := VerifyCert(cert, withQuoteVerifier(parseFixtureQuote))
			if err != nil {
				t.Fatal(err)
			}
			hash, ok := result.BootEvent("compose-hash")
			if !ok || hex.EncodeToString(hash) != composeHash {
				t.Fatalf("unexpected attested compose hash: %x", hash)
			}
		})
	}
}

func TestVerifyCertRequiresBoundEvidence(t *testing.T) {
	cert := readCertificate(t, "tdx-lite-v1-issue-cert.pem")
	t.Run("runtime_events_must_match_quote", func(t *testing.T) {
		differentMeasurement := withQuoteVerifier(func(raw []byte, url string) (*dcap.VerifiedReport, *dcap.Quote, error) {
			report, quote, err := parseFixtureQuote(raw, url)
			if err == nil {
				quote.Report.RTMR3[0] ^= 1
			}
			return report, quote, err
		})
		if result, err := VerifyCert(cert, differentMeasurement); err == nil || result != nil {
			t.Fatal("accepted runtime events with a different quoted measurement")
		}
	})
	t.Run("certificate_key_must_match_quote", func(t *testing.T) {
		other := *cert
		other.RawSubjectPublicKeyInfo = []byte("wrong key")
		if result, err := VerifyCert(&other, withQuoteVerifier(parseFixtureQuote)); err == nil || result != nil {
			t.Fatal("accepted a different certificate key")
		}
	})
}

func TestV2Replay(t *testing.T) {
	eventLog := []byte(`[{"imr":3,"event_type":134217729,"event":"compose-hash","event_payload":"abcd","version":2,
		"digest":"9dde1673f544faa94b921825209593ddde08d0baf9cd6990175dffaf3081f1bb10311d56de189491feb33842a050ad7b",
		"preimage":"7b226e616d65223a22636f6d706f73652d68617368222c227061796c6f6164223a2261626364222c2274797065223a3133343231373732397d"}]`)
	events, err := decodeTDXEvents(eventLog)
	if err != nil {
		t.Fatal(err)
	}
	// The RTMR3 measurement of this V2 event under the guest's wire format.
	register, err := hex.DecodeString("6b5684141bb1f141c6af192d97d0bae1ef1b2245e3bec30d7b24b07650a09446e3782019784af02abd6e1bdf202c98b8")
	if err != nil {
		t.Fatal(err)
	}
	if err := replayRTMR3(events, &dcap.Quote{Report: dcap.QuoteReport{RTMR3: register}}); err != nil {
		t.Fatal(err)
	}
}

func TestTLSRejectingPolicy(t *testing.T) {
	denied := errors.New("policy rejected")
	cfg := TLSConfig(withQuoteVerifier(parseFixtureQuote), WithVerify(func(*VerifyResult) error { return denied }))
	cert := readCertificate(t, "tdx-lite-v1-issue-cert.pem")
	if cfg.VerifyPeerCertificate == nil || cfg.VerifyConnection == nil {
		t.Fatal("policy check must apply to full and resumed handshakes")
	}
	if err := cfg.VerifyPeerCertificate([][]byte{cert.Raw}, nil); !errors.Is(err, denied) {
		t.Fatalf("full handshake: got %v", err)
	}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, DidResume: true}
	if err := cfg.VerifyConnection(state); !errors.Is(err, denied) {
		t.Fatalf("resumed handshake: got %v", err)
	}
}
