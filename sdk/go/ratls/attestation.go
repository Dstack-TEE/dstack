// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package ratls

import (
	"bytes"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	dcap "github.com/Phala-Network/dcap-qvl/golang-bindings"
	"github.com/vmihailenco/msgpack/v5"
	"github.com/vmihailenco/msgpack/v5/msgpcode"
)

var oidAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62397, 1, 8}

const maxAttestationBytes = 10 * 1024 * 1024

// Bound the in-memory event slice independently of the byte limit (roughly
// 3 MiB of RuntimeEvent slots on 64-bit platforms).
const maxRuntimeEvents = 65536

// RuntimeEvent is a measured dstack runtime event. Version 1 is the default.
type RuntimeEvent struct {
	Event   string       `msgpack:"event"`
	Payload msgpackBytes `msgpack:"payload"`
	Version uint32       `msgpack:"version"`
}

type msgpackBytes []byte

func (b *msgpackBytes) DecodeMsgpack(dec *msgpack.Decoder) error {
	code, err := dec.PeekCode()
	if err != nil {
		return err
	}
	if msgpcode.IsFixedArray(code) || code == msgpcode.Array16 || code == msgpcode.Array32 {
		n, err := dec.DecodeArrayLen()
		if err != nil {
			return err
		}
		if n < 0 || n > maxAttestationBytes {
			return fmt.Errorf("invalid byte array length")
		}
		v := make([]byte, n)
		for i := range v {
			code, err := dec.PeekCode()
			if err != nil {
				return err
			}
			x, err := dec.DecodeUint64()
			if err != nil {
				return err
			}
			if code == msgpcode.Nil || x > 255 {
				return fmt.Errorf("invalid byte array element")
			}
			v[i] = byte(x)
		}
		*b = v
		return nil
	}
	if !msgpcode.IsBin(code) {
		return fmt.Errorf("expected byte array or binary")
	}
	v, err := dec.DecodeBytes()
	if err != nil {
		return err
	}
	*b = v
	return nil
}

type wireRuntimeEvents []RuntimeEvent

func (events *wireRuntimeEvents) DecodeMsgpack(dec *msgpack.Decoder) error {
	n, err := dec.DecodeArrayLen()
	if err != nil {
		return err
	}
	if n < 0 || n > maxRuntimeEvents {
		return fmt.Errorf("invalid runtime event count")
	}
	out := make([]RuntimeEvent, n)
	for i := range out {
		var e struct {
			Event   *string       `msgpack:"event"`
			Payload *msgpackBytes `msgpack:"payload"`
			Version uint64        `msgpack:"version"`
		}
		e.Version = 1 // omitted in V1; an explicitly encoded zero is invalid
		if err := dec.Decode(&e); err != nil {
			return err
		}
		if e.Event == nil || !utf8.ValidString(*e.Event) || e.Payload == nil || (e.Version != 1 && e.Version != 2) {
			return fmt.Errorf("invalid runtime event fields at index %d", i)
		}
		out[i] = RuntimeEvent{Event: *e.Event, Payload: *e.Payload, Version: uint32(e.Version)}
	}
	*events = out
	return nil
}

type wireAttestation struct {
	Version  uint64 `msgpack:"version"`
	Platform struct {
		Kind string `msgpack:"kind"`
		Data struct {
			Quote msgpackBytes `msgpack:"quote"`
		} `msgpack:"data"`
	} `msgpack:"platform"`
	Stack struct {
		Kind string `msgpack:"kind"`
		Data struct {
			ReportData    msgpackBytes      `msgpack:"report_data"`
			RuntimeEvents wireRuntimeEvents `msgpack:"runtime_events"`
		} `msgpack:"data"`
	} `msgpack:"stack"`
}

func extractAttestation(cert *x509.Certificate) ([]byte, []RuntimeEvent, error) {
	encoded, err := getExtensionBytes(cert, oidAttestation)
	if err != nil {
		return nil, nil, fmt.Errorf("ratls: invalid attestation extension: %w", err)
	}
	if encoded != nil {
		if len(encoded) == 0 || len(encoded) > maxAttestationBytes {
			return nil, nil, fmt.Errorf("ratls: invalid attestation size")
		}
		var quote, reportData []byte
		var events []RuntimeEvent
		if encoded[0] == 0 {
			quote, events, reportData, err = decodeLegacyAttestation(encoded)
		} else {
			var wire wireAttestation
			err = decodeMsgpackAttestation(encoded, &wire)
			if err == nil && (wire.Version != 1 || wire.Platform.Kind != "tdx" || wire.Stack.Kind != "dstack") {
				err = fmt.Errorf("unsupported attestation version or platform")
			}
			quote, events, reportData = wire.Platform.Data.Quote, wire.Stack.Data.RuntimeEvents, wire.Stack.Data.ReportData
		}
		if err != nil {
			return nil, nil, fmt.Errorf("ratls: invalid versioned attestation: %w", err)
		}
		expected := sha512.Sum512(append([]byte("ratls-cert:"), cert.RawSubjectPublicKeyInfo...))
		if !bytes.Equal(reportData, expected[:]) {
			return nil, nil, fmt.Errorf("ratls: attestation report_data is not bound to the certificate")
		}
		if len(quote) == 0 {
			return nil, nil, fmt.Errorf("ratls: empty TDX quote")
		}
		return quote, events, nil
	}
	quote, err := getExtensionBytes(cert, oidTdxQuote)
	if err != nil {
		return nil, nil, fmt.Errorf("ratls: failed to parse quote extension: %w", err)
	}
	if quote == nil {
		return nil, nil, fmt.Errorf("ratls: certificate has no TDX quote extension (OID %s)", oidTdxQuote)
	}
	raw, err := getExtensionBytes(cert, oidEventLog)
	if err != nil {
		return nil, nil, fmt.Errorf("ratls: failed to parse event log extension: %w", err)
	}
	if raw == nil {
		return nil, nil, fmt.Errorf("ratls: certificate has TDX quote but no event log extension")
	}
	events, err := decodeTDXEvents(raw)
	return quote, events, err
}

func decodeTDXEvents(raw []byte) ([]RuntimeEvent, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("ratls: invalid UTF-8 in event log")
	}
	var entries []tdxEvent
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("ratls: invalid event log: %w", err)
	}
	var events []RuntimeEvent
	for i, e := range entries {
		if e.EventType != dstackRuntimeEventType {
			continue
		}
		event := RuntimeEvent{Event: e.Event, Payload: msgpackBytes(e.EventPayload), Version: uint32(e.Version)}
		if event.Version == 2 {
			canonical, err := event.preimage()
			if err != nil {
				return nil, err
			}
			preimage, err := hex.DecodeString(e.Preimage)
			digest := sha512.Sum384(canonical)
			if err != nil || !bytes.Equal(canonical, preimage) || !bytes.Equal(digest[:], e.Digest) {
				return nil, fmt.Errorf("ratls: inconsistent V2 digest or preimage at event %d", i)
			}
		}
		events = append(events, event)
	}
	return events, nil
}

func replayRTMR3(events []RuntimeEvent, quote *dcap.Quote) error {
	if len(quote.Report.RTMR3) == 0 {
		return nil
	}
	mr := make([]byte, 48)
	for _, e := range events {
		preimage, err := e.preimage()
		if err != nil {
			return err
		}
		digest := sha512.Sum384(preimage)
		h := sha512.New384()
		h.Write(mr)
		h.Write(digest[:])
		mr = h.Sum(nil)
	}
	if !bytes.Equal(mr, quote.Report.RTMR3) {
		return fmt.Errorf("ratls: RTMR3 mismatch: replayed %x, quoted %x", mr, quote.Report.RTMR3)
	}
	return nil
}

func (e RuntimeEvent) preimage() ([]byte, error) {
	switch e.Version {
	case 0, 1:
		if strings.ContainsRune(e.Event, ':') {
			return nil, fmt.Errorf("ratls: V1 runtime event name must not contain ':'")
		}
		preimage := make([]byte, 4)
		binary.LittleEndian.PutUint32(preimage, dstackRuntimeEventType)
		preimage = append(preimage, ':')
		preimage = append(preimage, e.Event...)
		preimage = append(preimage, ':')
		return append(preimage, e.Payload...), nil
	case 2:
		var out bytes.Buffer
		encoder := json.NewEncoder(&out)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(struct {
			Name    string `json:"name"`
			Payload string `json:"payload"`
			Type    uint32 `json:"type"`
		}{e.Event, hex.EncodeToString(e.Payload), dstackRuntimeEventType}); err != nil {
			return nil, err
		}
		return []byte(unescapeSeparators(strings.TrimSuffix(out.String(), "\n"))), nil
	default:
		return nil, fmt.Errorf("ratls: unsupported runtime event version %d", e.Version)
	}
}

func unescapeSeparators(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case strings.HasPrefix(s[i:], `\u2028`):
			b.WriteRune('\u2028')
			i += 5
		case strings.HasPrefix(s[i:], `\u2029`):
			b.WriteRune('\u2029')
			i += 5
		case s[i] == '\\' && i+1 < len(s):
			b.WriteString(s[i : i+2])
			i++
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// SCALE encodes a compact unsigned length before each vector.
type scaleReader struct{ *bytes.Reader }

func (r scaleReader) compact() (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	switch first & 3 {
	case 0:
		return uint64(first >> 2), nil
	case 1:
		b, err := r.ReadByte()
		n := uint64(uint16(first)|uint16(b)<<8) >> 2
		if err == nil && n < 1<<6 {
			return 0, fmt.Errorf("noncanonical SCALE length")
		}
		return n, err
	case 2:
		var b [3]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		n := uint64(uint32(first)|uint32(b[0])<<8|uint32(b[1])<<16|uint32(b[2])<<24) >> 2
		if n < 1<<14 {
			return 0, fmt.Errorf("noncanonical SCALE length")
		}
		return n, nil
	default:
		return 0, fmt.Errorf("ratls: oversized SCALE length")
	}
}
func (r scaleReader) vec() ([]byte, error) {
	n, err := r.compact()
	if err != nil {
		return nil, err
	}
	if n > uint64(r.Len()) {
		return nil, io.ErrUnexpectedEOF
	}
	v := make([]byte, int(n))
	_, err = io.ReadFull(r, v)
	return v, err
}
func decodeLegacyAttestation(data []byte) ([]byte, []RuntimeEvent, []byte, error) {
	r := scaleReader{bytes.NewReader(data)}
	version, err := r.ReadByte()
	if err != nil || version != 0 {
		return nil, nil, nil, fmt.Errorf("invalid SCALE version")
	}
	platform, err := r.ReadByte()
	if err != nil || platform != 0 {
		return nil, nil, nil, fmt.Errorf("unsupported SCALE platform")
	}
	quote, err := r.vec()
	if err != nil {
		return nil, nil, nil, err
	}
	count, err := r.compact()
	if err != nil || count > uint64(r.Len()/10) {
		return nil, nil, nil, fmt.Errorf("invalid event log length")
	}
	for i := uint64(0); i < count; i++ {
		var fields [8]byte
		if _, err = io.ReadFull(r, fields[:]); err != nil {
			return nil, nil, nil, err
		}
		for j := 0; j < 3; j++ {
			if _, err = r.vec(); err != nil {
				return nil, nil, nil, err
			}
		}
	}
	count, err = r.compact()
	if err != nil || count > maxRuntimeEvents || count > uint64(r.Len()/2) {
		return nil, nil, nil, fmt.Errorf("invalid runtime event count")
	}
	events := make([]RuntimeEvent, 0, int(count))
	for i := uint64(0); i < count; i++ {
		name, e := r.vec()
		if e != nil {
			return nil, nil, nil, e
		}
		if !utf8.Valid(name) {
			return nil, nil, nil, fmt.Errorf("invalid UTF-8 in SCALE event name")
		}
		payload, e := r.vec()
		if e != nil {
			return nil, nil, nil, e
		}
		events = append(events, RuntimeEvent{Event: string(name), Payload: payload})
	}
	report := make([]byte, 64)
	if _, err = io.ReadFull(r, report); err != nil {
		return nil, nil, nil, err
	}
	if _, err = r.vec(); err != nil {
		return nil, nil, nil, err
	}
	if r.Len() != 0 {
		return nil, nil, nil, fmt.Errorf("trailing SCALE bytes")
	}
	return quote, events, report, nil
}
