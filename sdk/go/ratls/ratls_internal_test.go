// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package ratls

import (
	"bytes"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
	"testing"

	dcap "github.com/Phala-Network/dcap-qvl/golang-bindings"
)

func TestTLSRejectingPolicy(t *testing.T) {
	denied := errors.New("policy rejected")
	cfg := tlsConfigWithVerifier(func(_ *x509.Certificate, opts ...Option) (*VerifyResult, error) {
		result := &VerifyResult{}
		if err := buildConfig(opts).applyPolicy(result); err != nil {
			return nil, err
		}
		return result, nil
	}, WithVerify(func(*VerifyResult) error { return denied }))
	data, err := os.ReadFile("tdx-lite-v1-issue-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if err := cfg.VerifyPeerCertificate([][]byte{block.Bytes}, [][]*x509.Certificate{}); !errors.Is(err, denied) {
		t.Fatalf("got %v", err)
	}
	var _ *tls.Config = cfg
}

func TestRejectingPolicy(t *testing.T) {
	denied := errors.New("policy rejected")
	cfg := buildConfig([]Option{WithVerify(func(*VerifyResult) error { return denied })})
	if err := cfg.applyPolicy(&VerifyResult{}); !errors.Is(err, denied) {
		t.Fatalf("got %v", err)
	}
}

// Captured from the current v1 IssueCert service; see dstack/verifier/fixtures/tdx-lite-v1.README.md.
func TestCurrentCertificateAttestation(t *testing.T) {
	for _, path := range []string{"tdx-lite-v1-issue-cert.pem", "tdx-lite-v0-get-tls-key.pem"} {
		t.Run(path, func(t *testing.T) { testCurrentCertificate(t, path) })
	}
}

func testCurrentCertificate(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("invalid pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	rawQuote, events, err := extractAttestation(cert)
	if err != nil {
		t.Fatal(err)
	}
	quote, err := dcap.ParseQuote(rawQuote)
	if err != nil {
		t.Fatal(err)
	}
	if err := replayRTMR3(events, quote); err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("no authenticated runtime events")
	}
}

func TestLegacyAttestationAndFallback(t *testing.T) {
	cert := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("public key")}
	report := sha512.Sum512(append([]byte("ratls-cert:"), cert.RawSubjectPublicKeyInfo...))
	// V0, TDX, quote vector, empty platform event log, one runtime event,
	// report_data and empty config. SCALE vector lengths are compact encoded.
	wire := append([]byte{0, 0, 4, 42, 0, 4, 4, 'x', 4, 7}, report[:]...)
	wire = append(wire, 0)
	ext, _ := asn1.Marshal(wire)
	cert.Extensions = []pkix.Extension{{Id: oidAttestation, Value: ext}}
	quote, events, err := extractAttestation(cert)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(quote, []byte{42}) || len(events) != 1 || events[0].Event != "x" || !bytes.Equal(events[0].Payload, []byte{7}) {
		t.Fatalf("unexpected decoded values %x %+v", quote, events)
	}
	cert.Extensions = nil
	quoteExt, _ := asn1.Marshal([]byte{9})
	logExt, _ := asn1.Marshal([]byte(`[]`))
	cert.Extensions = []pkix.Extension{{Id: oidTdxQuote, Value: quoteExt}, {Id: oidEventLog, Value: logExt}}
	quote, _, err = extractAttestation(cert)
	if err != nil || !bytes.Equal(quote, []byte{9}) {
		t.Fatalf("legacy extensions: %x %v", quote, err)
	}
	cert.Extensions = append(cert.Extensions, pkix.Extension{Id: oidAttestation, Value: ext})
	quote, _, err = extractAttestation(cert)
	if err != nil || !bytes.Equal(quote, []byte{42}) {
		t.Fatalf("versioned precedence: %x %v", quote, err)
	}
	cert.Extensions[2].Value, _ = asn1.Marshal([]byte{255})
	if _, _, err = extractAttestation(cert); err == nil {
		t.Fatal("malformed versioned attestation fell back")
	}
	cert.Extensions[2].Value, _ = asn1.Marshal(make([]byte, maxAttestationBytes+1))
	if _, _, err = extractAttestation(cert); err == nil {
		t.Fatal("accepted oversized attestation")
	}
}

func TestV2Replay(t *testing.T) {
	eventLog := []byte(`[{"imr":3,"event_type":134217729,"event":"compose-hash","event_payload":"abcd","version":2}]`)
	ext, err := asn1.Marshal(eventLog)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{Extensions: []pkix.Extension{{Id: oidEventLog, Value: ext}}}
	digest := sha512.Sum384([]byte(`{"name":"compose-hash","payload":"abcd","type":134217729}`))
	h := sha512.New384()
	h.Write(make([]byte, 48))
	h.Write(digest[:])
	quote := &dcap.Quote{Report: dcap.QuoteReport{RTMR3: h.Sum(nil)}}
	if err := verifyRTMR3(cert, quote); err != nil {
		t.Fatal(err)
	}
	quote.Report.RTMR3[0] ^= 1
	if err := verifyRTMR3(cert, quote); err == nil {
		t.Fatal("accepted altered RTMR3")
	}
	if err := replayRTMR3([]RuntimeEvent{{Version: 3}}, quote); err == nil {
		t.Fatal("accepted unknown event version")
	}
}

func TestEventCanonicalUnicode(t *testing.T) {
	event := RuntimeEvent{Event: "<&\u2028\\u2028", Payload: []byte{255}, Version: 2}
	canonical := "{\"name\":\"<&\u2028\\\\u2028\",\"payload\":\"ff\",\"type\":134217729}"
	digest := sha512.Sum384([]byte(canonical))
	h := sha512.New384()
	h.Write(make([]byte, 48))
	h.Write(digest[:])
	quote := &dcap.Quote{Report: dcap.QuoteReport{RTMR3: h.Sum(nil)}}
	if err := replayRTMR3([]RuntimeEvent{event}, quote); err != nil {
		t.Fatal(err)
	}
}
