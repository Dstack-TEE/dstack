// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// Package ratls provides RA-TLS certificate verification for dstack TEE applications.
//
// RA-TLS embeds TDX attestation quotes into X.509 certificate extensions.
// This package extracts and verifies those quotes, proving the certificate
// holder is running inside a genuine TEE.
package ratls

import (
	"bytes"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"

	dcap "github.com/Phala-Network/dcap-qvl/golang-bindings"
)

// Phala RA-TLS OIDs for certificate extensions.
var (
	oidTdxQuote = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62397, 1, 1}
	oidEventLog = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62397, 1, 2}
)

// DefaultPCCSURL is the default PCCS server for collateral fetching.
const DefaultPCCSURL = "https://pccs.phala.network"

// dstackRuntimeEventType is the event type for dstack runtime events (0x08000001).
// Matches Rust: cc_eventlog::runtime_events::DSTACK_RUNTIME_EVENT_TYPE
const dstackRuntimeEventType uint32 = 0x08000001

// VerifyResult contains the result of a successful RA-TLS verification.
type VerifyResult struct {
	// Report is the dcap-qvl verification report including TCB status and advisory IDs.
	Report *dcap.VerifiedReport
	// Quote is the parsed TDX quote structure with measurements and report data.
	Quote *dcap.Quote
	// RuntimeEvents are authenticated by replay against RTMR3, in order. Events
	// after system-ready are app-controlled and untrusted for identity policy;
	// use BootEvent for boot-time identity lookup.
	RuntimeEvents []RuntimeEvent
}

// BootEvent returns the first matching boot-time event payload. Events at and
// after system-ready are excluded because the application can emit them.
func (r *VerifyResult) BootEvent(name string) ([]byte, bool) {
	for _, event := range r.RuntimeEvents {
		if event.Event == "system-ready" {
			break
		}
		if event.Event == name {
			return bytes.Clone(event.Payload), true
		}
	}
	return nil, false
}

// BootEvents returns all matching boot-time event payloads in event order.
// Events at and after system-ready are excluded because the application can emit them.
func (r *VerifyResult) BootEvents(name string) [][]byte {
	var payloads [][]byte
	for _, event := range r.RuntimeEvents {
		if event.Event == "system-ready" {
			break
		}
		if event.Event == name {
			payloads = append(payloads, bytes.Clone(event.Payload))
		}
	}
	return payloads
}

// Option configures RA-TLS verification.
type Option func(*config)

type config struct {
	pccsURL     string
	onVerified  func(*VerifyResult)
	verify      func(*VerifyResult) error
	verifyQuote func([]byte, string) (*dcap.VerifiedReport, *dcap.Quote, error)
}

// WithPCCSURL sets the PCCS server URL for collateral fetching.
func WithPCCSURL(url string) Option {
	return func(c *config) { c.pccsURL = url }
}

// WithOnVerified sets a callback invoked after successful verification.
// Use this with TLSConfig to inspect the VerifyResult.
func WithOnVerified(fn func(*VerifyResult)) Option {
	return func(c *config) { c.onVerified = fn }
}

// WithVerify rejects an attested peer when fn returns an error. Use it to
// enforce the expected application, OS and compose identity. A nil function
// rejects verification rather than silently disabling policy.
func WithVerify(fn func(*VerifyResult) error) Option {
	return func(c *config) {
		if fn == nil {
			c.verify = func(*VerifyResult) error { return fmt.Errorf("ratls: nil verification policy") }
			return
		}
		c.verify = fn
	}
}

func (c *config) applyPolicy(result *VerifyResult) error {
	if c.verify != nil {
		return c.verify(result)
	}
	return nil
}

func withQuoteVerifier(fn func([]byte, string) (*dcap.VerifiedReport, *dcap.Quote, error)) Option {
	return func(c *config) { c.verifyQuote = fn }
}

func verifyQuote(raw []byte, pccsURL string) (*dcap.VerifiedReport, *dcap.Quote, error) {
	report, err := dcap.GetCollateralAndVerify(raw, pccsURL)
	if err != nil {
		return nil, nil, fmt.Errorf("quote verification failed: %w", err)
	}
	quote, err := dcap.ParseQuote(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse quote structure: %w", err)
	}
	return report, quote, nil
}

func buildConfig(opts []Option) *config {
	cfg := &config{pccsURL: DefaultPCCSURL, verifyQuote: verifyQuote}
	for _, o := range opts {
		o(cfg)
	}
	return cfg
}

// VerifyCert verifies that an X.509 certificate is a valid RA-TLS certificate.
//
// It extracts the embedded TDX quote, verifies it via dcap-qvl, checks that the
// quote's report_data binds to the certificate's public key, validates TCB
// attributes (debug mode, signer), and replays RTMR3 from the event log.
// Only dstack TDX is supported: gcp-tdx, nitro, sev-snp, and dstack-pod
// evidence are rejected. TLSConfig alone is not application authentication;
// use WithVerify to enforce trusted application, OS, and compose policy.
func VerifyCert(cert *x509.Certificate, opts ...Option) (*VerifyResult, error) {
	cfg := buildConfig(opts)

	// The versioned attestation takes precedence over legacy extensions.
	rawQuote, events, err := extractAttestation(cert)
	if err != nil {
		return nil, err
	}

	// Verify the quote and parse the report fields.
	report, quote, err := cfg.verifyQuote(rawQuote, cfg.pccsURL)
	if err != nil {
		return nil, fmt.Errorf("ratls: %w", err)
	}

	if quote.Report.Type != "TD10" && quote.Report.Type != "TD15" {
		return nil, fmt.Errorf("ratls: expected a TDX quote, got %s", quote.Report.Type)
	}
	if len(quote.Report.RTMR3) != 48 || len(quote.Report.ReportData) != 64 {
		return nil, fmt.Errorf("ratls: invalid TDX report lengths")
	}

	// 4. Validate TCB attributes
	//    Matches Rust: dstack_attest::attestation::validate_tcb()
	if err := validateTCB(quote); err != nil {
		return nil, fmt.Errorf("ratls: TCB validation failed: %w", err)
	}

	// 5. Verify report_data binds to the certificate's public key
	//    Format: SHA512("ratls-cert:" + SubjectPublicKeyInfo DER)
	//    Matches Rust: QuoteContentType::RaTlsCert.to_report_data(cert.public_key().raw)
	h := sha512.New()
	h.Write([]byte("ratls-cert:"))
	h.Write(cert.RawSubjectPublicKeyInfo)
	expected := h.Sum(nil)

	if !bytes.Equal(expected, []byte(quote.Report.ReportData)) {
		return nil, fmt.Errorf(
			"ratls: report_data mismatch: quote is not bound to this certificate's public key"+
				" (expected %x, got %x)", expected[:8], []byte(quote.Report.ReportData)[:8],
		)
	}

	// 6. Replay RTMR3 from event log and compare with quote
	//    Matches Rust: Attestation::replay_runtime_events::<Sha384>(None)
	if err := replayRTMR3(events, quote); err != nil {
		return nil, err
	}

	result := &VerifyResult{Report: report, Quote: quote, RuntimeEvents: events}
	if err := cfg.applyPolicy(result); err != nil {
		return nil, err
	}
	return result, nil
}

// validateTCB checks TCB attributes to reject debug mode and invalid signers.
// Matches Rust: dstack_attest::attestation::validate_tcb()
func validateTCB(quote *dcap.Quote) error {
	switch quote.Report.Type {
	case "TD10":
		// td_attributes[0] bit 0 = debug
		if len(quote.Report.TdAttributes) > 0 && quote.Report.TdAttributes[0]&0x01 != 0 {
			return fmt.Errorf("debug mode is not allowed")
		}
		// mr_signer_seam must be all zeros
		if len(quote.Report.MrSignerSeam) > 0 && !isAllZeros(quote.Report.MrSignerSeam) {
			return fmt.Errorf("invalid mr_signer_seam")
		}
	case "TD15":
		// mr_service_td must be all zeros
		if len(quote.Report.MrServiceTD) > 0 && !isAllZeros(quote.Report.MrServiceTD) {
			return fmt.Errorf("invalid mr_service_td")
		}
		// TD15 includes TD10 checks
		if len(quote.Report.TdAttributes) > 0 && quote.Report.TdAttributes[0]&0x01 != 0 {
			return fmt.Errorf("debug mode is not allowed")
		}
		if len(quote.Report.MrSignerSeam) > 0 && !isAllZeros(quote.Report.MrSignerSeam) {
			return fmt.Errorf("invalid mr_signer_seam")
		}
	case "SGX":
		// attributes[0] bit 1 = debug
		if len(quote.Report.Attributes) > 0 && quote.Report.Attributes[0]&0x02 != 0 {
			return fmt.Errorf("debug mode is not allowed")
		}
	default:
		return fmt.Errorf("unknown report type: %s", quote.Report.Type)
	}
	return nil
}

// tdxEvent matches the JSON format of cc_eventlog::tdx::TdxEvent.
// Note: digest and event_payload are hex-encoded in JSON (Rust uses serde_human_bytes).
type tdxEvent struct {
	IMR          uint32        `json:"imr"`
	EventType    uint32        `json:"event_type"`
	Digest       dcap.HexBytes `json:"digest"`
	Event        string        `json:"event"`
	EventPayload dcap.HexBytes `json:"event_payload"`
	Version      uint32        `json:"version"`
}

// verifyRTMR3 extracts the event log from the certificate, replays runtime events
// using SHA384, and compares the result with the quote's RTMR3 value.
// Matches Rust: Attestation::verify_tdx() RTMR3 replay
func verifyRTMR3(cert *x509.Certificate, quote *dcap.Quote) error {
	if len(quote.Report.RTMR3) == 0 {
		return nil // Not a TDX quote, skip
	}

	rawEventLog, err := getExtensionBytes(cert, oidEventLog)
	if err != nil {
		return fmt.Errorf("ratls: failed to parse event log extension: %w", err)
	}
	if rawEventLog == nil {
		return fmt.Errorf("ratls: certificate has TDX quote but no event log extension")
	}

	var events []tdxEvent
	if err := json.Unmarshal(rawEventLog, &events); err != nil {
		return fmt.Errorf("ratls: failed to parse event log JSON: %w", err)
	}

	return replayRTMR3(eventsFromTDX(events), quote)
}

// TLSConfig returns a *tls.Config that verifies the server's RA-TLS certificate
// during the TLS handshake.
//
// Standard CA chain verification is skipped because RA-TLS certificates are
// self-signed; trust is established through hardware attestation instead.
// TLSConfig alone does not authenticate the application, OS, or compose. Use
// WithVerify to compare verified measurements and boot-time events to trusted policy.
// Use VerifyResult.BootEvent rather than scanning events after system-ready.
func TLSConfig(opts ...Option) *tls.Config {
	return tlsConfigWithVerifier(VerifyCert, opts...)
}

func tlsConfigWithVerifier(verify func(*x509.Certificate, ...Option) (*VerifyResult, error), opts ...Option) *tls.Config {
	cfg := buildConfig(opts)
	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("ratls: server presented no certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("ratls: failed to parse server certificate: %w", err)
			}
			result, err := verify(cert, opts...)
			if err != nil {
				return err
			}
			if cfg.onVerified != nil {
				cfg.onVerified(result)
			}
			return nil
		},
	}
}

// getExtensionBytes finds a certificate extension by OID and unwraps
// the DER OCTET STRING to return the raw content bytes.
// Returns (nil, nil) if the extension is not present.
// Matches Rust: CertExt::get_extension_bytes() which calls
// yasna::parse_der(|reader| reader.read_bytes()) to unwrap OCTET STRING.
func getExtensionBytes(cert *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			var raw []byte
			if _, err := asn1.Unmarshal(ext.Value, &raw); err != nil {
				return nil, fmt.Errorf("failed to unmarshal extension value: %w", err)
			}
			return raw, nil
		}
	}
	return nil, nil
}

func isAllZeros(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
