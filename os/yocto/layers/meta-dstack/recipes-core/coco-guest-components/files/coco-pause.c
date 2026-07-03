// Minimal Kubernetes pause process for Kata/CoCo guest-pull sandbox containers.
// It is installed into /pause_bundle/rootfs/pause and linked statically because
// kata-agent copies only this executable into the synthesized pause rootfs.

#include <errno.h>
#include <signal.h>
#include <unistd.h>

static void exit_cleanly(int signo) {
    (void)signo;
    _exit(0);
}

int main(void) {
    struct sigaction sa;
    sa.sa_handler = exit_cleanly;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    for (;;) {
        pause();
        if (errno == EINTR) {
            continue;
        }
    }
}
