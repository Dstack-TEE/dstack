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

	dcap "github.com/Phala-Network/dcap-qvl/golang-bindings"
	"github.com/vmihailenco/msgpack/v5"
)

var oidAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62397, 1, 8}

const maxAttestationBytes = 10 * 1024 * 1024

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
	if code >= 0x90 && code <= 0x9f || code == 0xdc || code == 0xdd {
		n, err := dec.DecodeArrayLen()
		if err != nil {
			return err
		}
		if n < 0 || n > maxAttestationBytes {
			return fmt.Errorf("invalid byte array length")
		}
		v := make([]byte, n)
		for i := range v {
			x, err := dec.DecodeUint8()
			if err != nil {
				return err
			}
			v[i] = x
		}
		*b = v
		return nil
	}
	v, err := dec.DecodeBytes()
	if err != nil {
		return err
	}
	*b = v
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
			ReportData    msgpackBytes   `msgpack:"report_data"`
			RuntimeEvents []RuntimeEvent `msgpack:"runtime_events"`
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
			reader := bytes.NewReader(encoded)
			err = msgpack.NewDecoder(reader).Decode(&wire)
			if err == nil && reader.Len() != 0 {
				err = fmt.Errorf("trailing attestation bytes")
			}
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
	var entries []tdxEvent
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, nil, fmt.Errorf("ratls: invalid event log: %w", err)
	}
	return quote, eventsFromTDX(entries), nil
}

func eventsFromTDX(entries []tdxEvent) []RuntimeEvent {
	var events []RuntimeEvent
	for _, e := range entries {
		if e.EventType == dstackRuntimeEventType {
			events = append(events, RuntimeEvent{Event: e.Event, Payload: msgpackBytes(e.EventPayload), Version: e.Version})
		}
	}
	return events
}

func replayRTMR3(events []RuntimeEvent, quote *dcap.Quote) error {
	if len(quote.Report.RTMR3) == 0 {
		return nil
	}
	mr := make([]byte, 48)
	for _, e := range events {
		var preimage []byte
		switch e.Version {
		case 0, 1:
			preimage = make([]byte, 4)
			binary.LittleEndian.PutUint32(preimage, dstackRuntimeEventType)
			preimage = append(preimage, ':')
			preimage = append(preimage, e.Event...)
			preimage = append(preimage, ':')
			preimage = append(preimage, e.Payload...)
		case 2:
			var out bytes.Buffer
			encoder := json.NewEncoder(&out)
			encoder.SetEscapeHTML(false)
			if err := encoder.Encode(struct {
				Name    string `json:"name"`
				Payload string `json:"payload"`
				Type    uint32 `json:"type"`
			}{e.Event, hex.EncodeToString(e.Payload), dstackRuntimeEventType}); err != nil {
				return err
			}
			preimage = []byte(unescapeSeparators(strings.TrimSuffix(out.String(), "\n")))
		default:
			return fmt.Errorf("ratls: unsupported runtime event version %d", e.Version)
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
		return uint64(uint16(first)|uint16(b)<<8) >> 2, err
	case 2:
		var b [3]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		return uint64(uint32(first)|uint32(b[0])<<8|uint32(b[1])<<16|uint32(b[2])<<24) >> 2, nil
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
	if err != nil || count > uint64(r.Len()/2) {
		return nil, nil, nil, fmt.Errorf("invalid runtime event count")
	}
	events := make([]RuntimeEvent, 0, int(count))
	for i := uint64(0); i < count; i++ {
		name, e := r.vec()
		if e != nil {
			return nil, nil, nil, e
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
