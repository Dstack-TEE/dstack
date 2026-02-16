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
	"encoding/binary"
	"encoding/json"
	"fmt"

	dcap "github.com/Phala-Network/dcap-qvl/golang-bindings"
)

// Phala RA-TLS OIDs for certificate extensions.
var (
	oidTdxQuote  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62397, 1, 1}
	oidEventLog  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62397, 1, 2}
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
}

// Option configures RA-TLS verification.
type Option func(*config)

type config struct {
	pccsURL    string
	onVerified func(*VerifyResult)
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

func buildConfig(opts []Option) *config {
	cfg := &config{pccsURL: DefaultPCCSURL}
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
func VerifyCert(cert *x509.Certificate, opts ...Option) (*VerifyResult, error) {
	cfg := buildConfig(opts)

	// 1. Extract raw TDX quote from certificate extension (OID 1.1)
	rawQuote, err := getExtensionBytes(cert, oidTdxQuote)
	if err != nil {
		return nil, fmt.Errorf("ratls: failed to parse quote extension: %w", err)
	}
	if rawQuote == nil {
		return nil, fmt.Errorf("ratls: certificate has no TDX quote extension (OID %s)", oidTdxQuote)
	}

	// 2. Verify quote via dcap-qvl (fetch collateral from PCCS + verify Intel signature)
	report, err := dcap.GetCollateralAndVerify(rawQuote, cfg.pccsURL)
	if err != nil {
		return nil, fmt.Errorf("ratls: quote verification failed: %w", err)
	}

	// 3. Parse quote structure to access report fields
	quote, err := dcap.ParseQuote(rawQuote)
	if err != nil {
		return nil, fmt.Errorf("ratls: failed to parse quote structure: %w", err)
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
	if err := verifyRTMR3(cert, quote); err != nil {
		return nil, err
	}

	return &VerifyResult{Report: report, Quote: quote}, nil
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

	// Replay: accumulate SHA384 over runtime events
	// Matches Rust: cc_eventlog::runtime_events::replay_events::<Sha384>()
	mr := make([]byte, 48) // starts at all zeros

	for _, ev := range events {
		if ev.EventType != dstackRuntimeEventType {
			continue
		}

		// Compute event digest: SHA384(event_type_ne_bytes || ":" || event || ":" || payload)
		// Matches Rust: RuntimeEvent::digest::<Sha384>()
		// TDX CVMs run on x86_64 (little-endian), so to_ne_bytes() is LE.
		eventTypeBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(eventTypeBytes, ev.EventType)

		dh := sha512.New384()
		dh.Write(eventTypeBytes)
		dh.Write([]byte(":"))
		dh.Write([]byte(ev.Event))
		dh.Write([]byte(":"))
		dh.Write(ev.EventPayload)
		digest := dh.Sum(nil)

		// Extend: mr = SHA384(mr || digest)
		eh := sha512.New384()
		eh.Write(mr)
		eh.Write(digest)
		mr = eh.Sum(nil)
	}

	if !bytes.Equal(mr, []byte(quote.Report.RTMR3)) {
		return fmt.Errorf(
			"ratls: RTMR3 mismatch: replayed %x, quoted %x",
			mr[:8], []byte(quote.Report.RTMR3)[:8],
		)
	}
	return nil
}

// TLSConfig returns a *tls.Config that verifies the server's RA-TLS certificate
// during the TLS handshake.
//
// Standard CA chain verification is skipped because RA-TLS certificates are
// self-signed; trust is established through hardware attestation instead.
func TLSConfig(opts ...Option) *tls.Config {
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
			result, err := VerifyCert(cert, opts...)
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
