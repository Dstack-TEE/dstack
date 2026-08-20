# Application health checks

The gateway keeps an instance out of its app's load-balancing rotation while the
application is not able to serve. This page describes where that verdict comes
from and how an app influences it.

## Why this exists

A CVM registers with the gateway from `dstack-util setup`, during boot.
`app-compose.service` is ordered *after* `dstack-prepare.service`, so at the
moment of registration the application's containers do not exist yet — the image
may still be pulling. Without a health signal the only thing standing between a
freshly booted instance and a real request is the WireGuard handshake, which
says the tunnel is up and nothing about whether anything is listening behind it.

## Where the verdict comes from

The guest agent answers `Worker.Health`; the gateway polls it. Sources are
consulted in this order:

1. **`health_check` in `app-compose.json`** — if declared, it decides, for every
   runner.
2. **Container healthchecks** — for `docker-compose` and `nerdctl-compose`,
   every container that declares a Compose `healthcheck` must be reporting
   healthy.
3. **Nothing** — the app is treated as healthy. This is where an app lands when
   it declares no probe and none of its containers declare a healthcheck.

### Container healthchecks

Nothing to configure beyond what a Compose file already says:

```yaml
services:
  web:
    image: my-app:1.0
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS localhost:8080/healthz || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 3
```

Only containers that declare a `healthcheck` are judged. A container without one
is not evidence either way — the app has not said how to test it — so it is
skipped rather than counted as passing. `starting` counts as *not* healthy: that
state is precisely the boot window this exists to keep traffic out of.

Finding **no containers at all** is not healthy either. A runtime that answers
while having nothing to show means Compose has not got as far as creating
anything.

The `nerdctl-compose` runner needs **nerdctl >= 2.3.1** for Compose
`healthcheck:` to be honoured; earlier versions parse the field and discard it.
Container presence is still detected on older versions, so the boot-window gate
works regardless.

### `health_check` in `app-compose.json`

For the `bash` runner there are no containers to inspect, and an app may anyway
want to answer the question itself. Declare a program and the guest agent runs
it on a timer:

```json
{
  "manifest_version": 1,
  "name": "my-app",
  "runner": "bash",
  "bash_script": "/opt/my-app/run.sh &",
  "health_check": {
    "path": "/opt/my-app/healthz.sh",
    "args": ["--strict"],
    "interval_secs": 10,
    "timeout_secs": 5
  }
}
```

| Field | Default | Meaning |
|---|---|---|
| `path` | required | Program to run. Executed directly, **not** through a shell |
| `args` | `[]` | Arguments, passed verbatim |
| `interval_secs` | `10` | Seconds between runs |
| `timeout_secs` | `5` | A run that exceeds this is killed and counted as a failure |

Exit status 0 means healthy; anything else, including a timeout or a program
that cannot be executed, means not. The exit code and up to 512 bytes of stderr
are reported to the gateway for logging.

`path` is not a shell command line: nothing in it is word-split, glob-expanded
or variable-substituted. If you need shell semantics, point it at a script.

Declaring `health_check` **overrides** container healthchecks, so a Compose app
that wants one whole-application answer can give one instead of having every
container judged separately.

Before the first run completes, the app reports **not** healthy. Registration
happens long before the application is up, so "has not run yet" must not read as
a pass.

## How the gateway uses it

- Health only gates **app-id** routing. Addressing an instance directly by
  instance id is never gated, so an unhealthy instance stays reachable for
  investigation.
- **If no instance of an app reports healthy, the gateway routes to all of them
  anyway.** Health is inference and can be wrong — a misconfigured probe, an
  agent that died, a whole fleet failing for a reason unrelated to the app.
  Blackholing an app on that basis is worse than sending traffic to instances
  that might be fine.
- Health is a *per-node observation*. Each gateway node polls for itself and
  does not share the result, the same way each node reads its own WireGuard
  handshakes.
- An agent that predates `Worker.Health` is never polled and is always treated
  as healthy, so older guest images keep serving.

Operators can also take an instance out of rotation by hand with
`Admin.SetInstanceReady`, independently of health. That one is an instruction
rather than an inference, so it does **not** fail open: gating every instance of
an app means the app refuses new connections.

Polling is configured on the gateway:

```toml
[core.proxy.health_check]
enabled = true
interval = "5s"
timeout = "2s"
concurrency = 16
```

`enabled = false` restores the behaviour from before health polling existed:
every instance stays eligible regardless of what it reports.
