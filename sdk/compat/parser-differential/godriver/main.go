// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
)

func selectCase(sock, name string) {
	c, err := net.Dial("unix", sock)
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(c, "POST /__case/%s HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", name)
	buf := make([]byte, 4096)
	c.Read(buf)
	c.Close()
}

func clip(b []byte, n int) string {
	s := hex.EncodeToString(b)
	if len(s) > n {
		return s[:n]
	}
	return s
}

func main() {
	sock, name, method := os.Args[1], os.Args[2], os.Args[3]
	selectCase(sock, name)
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("PANIC|%v\n", r)
		}
	}()
	ctx := context.Background()
	var out string
	var err error
	if strings.HasPrefix(method, "v0") {
		c0 := dstack.NewDstackClientV0(dstack.WithEndpoint(sock))
		switch method {
		case "v0GetKey":
			r, e := c0.GetKey(ctx, "d", "", "")
			err = e
			if e == nil {
				k, de := r.DecodeKey()
				out = fmt.Sprintf("key=%.16s chain=%d decode=%s", r.Key, len(r.SignatureChain), tb(k, de))
			}
		case "v0Info":
			r, e := c0.Info(ctx)
			err = e
			if e == nil {
				ti, te := r.DecodeTcbInfo()
				if te == nil { out = fmt.Sprintf("app_id=%.16s tcb=ok mrtd=%.8s", r.AppID, ti.Mrtd) } else { out = fmt.Sprintf("app_id=%.16s tcb=<%v>", r.AppID, te) }
			}
		case "v0TlsKey":
			r, e := c0.GetTlsKey(ctx)
			err = e
			if e == nil {
				b32, e1 := r.AsUint8Array(32)
				bf, e2 := r.AsUint8Array()
				out = fmt.Sprintf("as32=%s fulllen=%s", tb(b32, e1), tb2(len(bf), e2))
			}
		}
		report(out, err)
		return
	}
	c := dstack.NewDstackClientV1(dstack.WithEndpoint(sock))
	switch method {
	case "GetKey":
		r, e := c.GetKey(ctx, "d", "secp256k1")
		err = e
		if e == nil {
			out = fmt.Sprintf("key=%s chain=%d", clip(r.Key, 16), len(r.SignatureChain))
		}
	case "Info":
		r, e := c.Info(ctx)
		err = e
		if e == nil {
			out = fmt.Sprintf("app_id=%s app_name=%q os_image_hash=%s", clip(r.AppID, 16), r.AppName, clip(r.OsImageHash, 16))
		}
	case "Attest":
		r, e := c.Attest(ctx, make([]byte, 32), false)
		err = e
		if e == nil {
			out = fmt.Sprintf("attestation=%dB gpu=%d", len(r.Attestation), len(r.BoottimeGpuEvidence))
		}
	}
	report(out, err)
}

func report(out string, err error) {
	if err != nil {
		m := strings.ReplaceAll(err.Error(), "\n", " ")
		if len(m) > 160 {
			m = m[:160]
		}
		fmt.Printf("ERR|%s\n", m)
		return
	}
	fmt.Printf("OK|%s\n", out)
}

func tb(b []byte, err error) string {
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return hex.EncodeToString(b)
}

func tb2(v interface{}, err error) string {
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return fmt.Sprintf("%v", v)
}
