// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

func proxy(listener net.Listener, socket string) {
	for {
		incoming, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		go func() {
			defer incoming.Close()
			upstream, err := net.Dial("unix", socket)
			if err != nil {
				return
			}
			defer upstream.Close()
			done := make(chan struct{}, 1)
			go func() { _, _ = io.Copy(upstream, incoming); done <- struct{}{} }()
			go func() { _, _ = io.Copy(incoming, upstream); done <- struct{}{} }()
			<-done
		}()
	}
}

func main() {
	if len(os.Args) < 2 {
		panic("expected PORT:SOCKET arguments")
	}
	for _, mapping := range os.Args[1:] {
		port, socket, ok := strings.Cut(mapping, ":")
		if !ok || port == "" || socket == "" {
			panic(fmt.Sprintf("invalid mapping: %s", mapping))
		}
		listener, err := net.Listen("tcp", ":"+port)
		if err != nil {
			panic(err)
		}
		go proxy(listener, socket)
	}
	select {}
}
