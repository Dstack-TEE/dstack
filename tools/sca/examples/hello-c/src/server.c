/* SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/* tiny static HTTP server for the sca hello-c example.
 * single-threaded, serves one fixed page. build with:
 *   musl-gcc -static -Os -s -o ../rootfs/run/sca/bin/app server.c
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

static const char *BODY =
"<!doctype html>\n"
"<h1>hello from a self-contained dstack app \xF0\x9F\x8E\x89</h1>\n"
"<p>This static C binary was embedded (base64) directly in <code>app-compose.json</code>,\n"
"extracted into a tmpfs rootfs at boot, and run by systemd \xE2\x80\x94 <b>no docker, no registry pull</b>.</p>\n"
"<p>The exact bytes are measured into the compose-hash / RTMR3.</p>\n";

int main(void) {
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons(8080);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) { perror("bind"); return 1; }
    if (listen(s, 16) < 0) { perror("listen"); return 1; }
    printf("hello-c: listening on :8080\n");
    fflush(stdout);
    for (;;) {
        int c = accept(s, 0, 0);
        if (c < 0) continue;
        char buf[2048];
        (void)read(c, buf, sizeof(buf));
        char hdr[256];
        int blen = (int)strlen(BODY);
        int n = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
            "Content-Length: %d\r\nConnection: close\r\n\r\n", blen);
        (void)write(c, hdr, n);
        (void)write(c, BODY, blen);
        close(c);
    }
}
