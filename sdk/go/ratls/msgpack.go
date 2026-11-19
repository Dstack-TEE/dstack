// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package ratls

import (
	"bytes"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/vmihailenco/msgpack/v5"
	"github.com/vmihailenco/msgpack/v5/msgpcode"
)

// The V1 schema uses fewer than ten nested containers. Allow headroom for
// unknown fields, which the typed decoder also traverses when skipping them.
const maxMsgpackDepth = 32

// Check the entire value before a typed decoder can allocate from a length
// prefix. bytes.Buffer implements io.ByteScanner, so Decoder does not read ahead.
func decodeMsgpackAttestation(data []byte, wire *wireAttestation) error {
	r := bytes.NewBuffer(data)
	dec := msgpack.NewDecoder(r)
	if err := checkMsgpackValue(r, dec, 0); err != nil {
		return err
	}
	if r.Len() != 0 {
		return fmt.Errorf("trailing attestation bytes")
	}
	return msgpack.Unmarshal(data, wire)
}

func checkMsgpackValue(r *bytes.Buffer, dec *msgpack.Decoder, depth int) error {
	if depth > maxMsgpackDepth {
		return fmt.Errorf("attestation exceeds maximum nesting depth")
	}
	code, err := dec.PeekCode()
	if err != nil {
		return err
	}

	var count int
	switch {
	case msgpcode.IsString(code), msgpcode.IsBin(code):
		n, err := dec.DecodeBytesLen()
		if err != nil {
			return err
		}
		if n < 0 || n > r.Len() {
			return io.ErrUnexpectedEOF
		}
		payload := r.Next(n)
		if msgpcode.IsString(code) && !utf8.Valid(payload) {
			return fmt.Errorf("invalid UTF-8 in MessagePack string")
		}
		return nil
	case msgpcode.IsFixedArray(code), code == msgpcode.Array16, code == msgpcode.Array32:
		count, err = dec.DecodeArrayLen()
	case msgpcode.IsFixedMap(code), code == msgpcode.Map16, code == msgpcode.Map32:
		count, err = dec.DecodeMapLen()
		if count < 0 || count > r.Len()/2 {
			return io.ErrUnexpectedEOF
		}
		count *= 2 // key and value
	case msgpcode.IsExt(code):
		_, n, err := dec.DecodeExtHeader()
		if err != nil {
			return err
		}
		if n < 0 || n > r.Len() {
			return io.ErrUnexpectedEOF
		}
		r.Next(n)
		return nil
	default:
		// The remaining scalar codes have at most eight payload bytes.
		return dec.Skip()
	}
	if err != nil {
		return err
	}
	if count < 0 || count > r.Len() {
		return io.ErrUnexpectedEOF
	}
	for i := 0; i < count; i++ {
		if err := checkMsgpackValue(r, dec, depth+1); err != nil {
			return err
		}
	}
	return nil
}
