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
	"io"
	"os"
	"testing"

	dcap "github.com/Phala-Network/dcap-qvl/golang-bindings"
	"github.com/vmihailenco/msgpack/v5"
)

func TestMsgpackByteArrayRange(t *testing.T) {
	for _, tc := range []struct {
		value any
		valid bool
	}{
		{[]uint16{0, 255}, true}, {[]uint16{0, 256}, false},
		{[]int16{0, -1}, false}, {[]any{0, nil}, false},
	} {
		data, err := msgpack.Marshal(tc.value)
		if err != nil {
			t.Fatal(err)
		}
		var decoded msgpackBytes
		err = msgpack.Unmarshal(data, &decoded)
		if (err == nil) != tc.valid || tc.valid && !bytes.Equal(decoded, []byte{0, 255}) {
			t.Errorf("decode %v: got %v, %v", tc.value, decoded, err)
		}
	}
}

func TestMsgpackFraming(t *testing.T) {
	for _, value := range []any{"text", []byte{1, 2}, []int{1, 2}, map[string]int{"n": 1}} {
		b, err := msgpack.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		// Check each length against the complete input and a short reader.
		for _, input := range [][]byte{b, b[:len(b)-1]} {
			r := bytes.NewBuffer(input)
			err := checkMsgpackValue(r, msgpack.NewDecoder(r), 0)
			if len(input) == len(b) {
				if err != nil || r.Len() != 0 {
					t.Fatalf("valid %T: remaining=%d, err=%v", value, r.Len(), err)
				}
			} else if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("short %T: got %v", value, err)
			}
		}
	}
}

func TestMsgpackSkipsExtensionInUnknownField(t *testing.T) {
	var value bytes.Buffer
	enc := msgpack.NewEncoder(&value)
	if err := enc.EncodeExtHeader(7, 1); err != nil {
		t.Fatal(err)
	}
	value.WriteByte(0x01)
	data, err := msgpack.Marshal(map[string]any{"version": 1, "future": msgpack.RawMessage(value.Bytes())})
	if err != nil {
		t.Fatal(err)
	}
	var wire wireAttestation
	if err := decodeMsgpackAttestation(data, &wire); err != nil || wire.Version != 1 {
		t.Fatalf("decode supported fields: version=%d, err=%v", wire.Version, err)
	}
}

func TestMsgpackNestingLimit(t *testing.T) {
	var v any = 1
	for i := 0; i <= maxMsgpackDepth; i++ {
		v = []any{v}
		if i < maxMsgpackDepth-1 {
			continue
		}
		b, err := msgpack.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		r := bytes.NewBuffer(b)
		err = checkMsgpackValue(r, msgpack.NewDecoder(r), 0)
		if (err != nil) != (i == maxMsgpackDepth) {
			t.Errorf("nesting depth %d: %v", i+1, err)
		}
	}
}

func TestRuntimeEventVersionRange(t *testing.T) {
	for _, version := range []any{nil, 0, -1, uint64(1)<<32 + 1, 1, 2} {
		input := []map[string]any{{"event": "boot", "payload": []byte{0}, "version": version}}
		b, err := msgpack.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		var events wireRuntimeEvents
		err = msgpack.Unmarshal(b, &events)
		valid := version == 1 || version == 2
		if (err == nil) != valid {
			t.Errorf("version %v: got %v", version, err)
		}
	}
}

func TestEventNameEncoding(t *testing.T) {
	for _, version := range []uint32{0, 1, 2} {
		p, err := (RuntimeEvent{Version: version, Event: "a:b"}).preimage()
		if version != 2 {
			if err == nil {
				t.Errorf("V1 accepted ':' in a name")
			}
		} else if err != nil || string(p) != `{"name":"a:b","payload":"","type":134217729}` {
			t.Errorf("V2 name: got %s, %v", p, err)
		}
	}
}

func TestExtensionOctetStringFraming(t *testing.T) {
	one, err := asn1.Marshal([]byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	if value, err := unwrapExtension(one); err != nil || string(value) != "one" {
		t.Fatalf("single DER value: got %q, %v", value, err)
	}
	if _, err := unwrapExtension(bytes.Repeat(one, 2)); err == nil {
		t.Fatal("accepted two DER values")
	}
}

func TestCompactLengthBoundaries(t *testing.T) {
	for _, tc := range []struct {
		enc   []byte
		want  uint64
		valid bool
	}{
		{[]byte{0xfc}, 63, true}, {[]byte{1, 1}, 64, true},
		{[]byte{0xfd, 0xff}, 16383, true}, {[]byte{2, 0, 1, 0}, 16384, true},
		{[]byte{1, 0}, 0, false}, {[]byte{2, 0, 0, 0}, 0, false},
	} {
		n, err := (scaleReader{bytes.NewReader(tc.enc)}).compact()
		if n != tc.want || (err == nil) != tc.valid {
			t.Errorf("%x: got %d, %v", tc.enc, n, err)
		}
	}
}

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

func TestNilVerifyRejected(t *testing.T) {
	if err := buildConfig([]Option{WithVerify(nil)}).applyPolicy(&VerifyResult{}); err == nil {
		t.Fatal("nil policy accepted")
	}
}

func TestVerifyCertOffline(t *testing.T) {
	for _, path := range []string{"tdx-lite-v1-issue-cert.pem", "tdx-lite-v0-get-tls-key.pem"} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(data)
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			for _, scenario := range []string{"valid", "tampered-spki", "tampered-report", "tampered-rtmr3", "debug", "signer", "quote-error", "policy-reject"} {
				t.Run(scenario, func(t *testing.T) {
					copyCert := *cert
					if scenario == "tampered-spki" {
						copyCert.RawSubjectPublicKeyInfo = []byte("wrong key")
					}
					called := false
					denied := errors.New("policy denied")
					expectedReport := &dcap.VerifiedReport{}
					var expectedQuote *dcap.Quote
					stub := withQuoteVerifier(func(raw []byte, _ string) (*dcap.VerifiedReport, *dcap.Quote, error) {
						if scenario == "quote-error" {
							return nil, nil, errors.New("invalid quote")
						}
						quote, err := dcap.ParseQuote(raw)
						if err != nil {
							return nil, nil, err
						}
						if scenario == "tampered-report" {
							quote.Report.ReportData[0] ^= 1
						}
						if scenario == "debug" {
							quote.Report.TdAttributes[0] |= 1
						}
						if scenario == "signer" {
							quote.Report.MrSignerSeam[0] = 1
						}
						if scenario == "tampered-rtmr3" {
							quote.Report.RTMR3[0] ^= 1
						}
						expectedQuote = quote
						return expectedReport, quote, nil
					})
					result, err := VerifyCert(&copyCert, stub, WithVerify(func(result *VerifyResult) error {
						called = true
						if result.Quote != expectedQuote || result.Report != expectedReport || len(result.RuntimeEvents) == 0 {
							t.Error("incomplete result")
						}
						if scenario == "policy-reject" {
							return denied
						}
						return nil
					}))
					if scenario == "valid" {
						if err != nil || result == nil || !called {
							t.Fatalf("result %v error %v called %v", result, err, called)
						}
						return
					}
					if err == nil || result != nil {
						t.Fatalf("accepted %s", scenario)
					}
					if scenario == "policy-reject" {
						if !called || !errors.Is(err, denied) {
							t.Fatalf("policy error %v called %v", err, called)
						}
					} else if called {
						t.Fatal("policy invoked before verification")
					}
				})
			}
		})
	}
}

func TestTLSRejectingPolicy(t *testing.T) {
	denied := errors.New("policy rejected")
	cfg := TLSConfig(withQuoteVerifier(func(raw []byte, _ string) (*dcap.VerifiedReport, *dcap.Quote, error) {
		quote, err := dcap.ParseQuote(raw)
		return &dcap.VerifiedReport{}, quote, err
	}), WithVerify(func(*VerifyResult) error { return denied }))
	data, err := os.ReadFile("tdx-lite-v1-issue-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
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
	state.DidResume = false
	if err := cfg.VerifyConnection(state); err != nil {
		t.Fatalf("full handshake already handled by peer verification: %v", err)
	}
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

func TestRejectDstackPod(t *testing.T) {
	data, err := os.ReadFile("tdx-lite-v1-issue-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := getExtensionBytes(cert, oidAttestation)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]interface{}
	if err := msgpack.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	wire["stack"].(map[string]interface{})["kind"] = "dstack-pod"
	raw, err = msgpack.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	ext, err := asn1.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range cert.Extensions {
		if cert.Extensions[i].Id.Equal(oidAttestation) {
			cert.Extensions[i].Value = ext
		}
	}
	if _, _, err := extractAttestation(cert); err == nil {
		t.Fatal("accepted dstack-pod evidence")
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
	eventLog := []byte(`[{"imr":3,"event_type":134217729,"event":"compose-hash","event_payload":"abcd","version":2,
		"digest":"9dde1673f544faa94b921825209593ddde08d0baf9cd6990175dffaf3081f1bb10311d56de189491feb33842a050ad7b",
		"preimage":"7b226e616d65223a22636f6d706f73652d68617368222c227061796c6f6164223a2261626364222c2274797065223a3133343231373732397d"}]`)
	events, err := decodeTDXEvents(eventLog)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384([]byte(`{"name":"compose-hash","payload":"abcd","type":134217729}`))
	h := sha512.New384()
	h.Write(make([]byte, 48))
	h.Write(digest[:])
	quote := &dcap.Quote{Report: dcap.QuoteReport{RTMR3: h.Sum(nil)}}
	if err := replayRTMR3(events, quote); err != nil {
		t.Fatal(err)
	}
	quote.Report.RTMR3[0] ^= 1
	if err := replayRTMR3(events, quote); err == nil {
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
