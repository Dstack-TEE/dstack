# Application health checks

The gateway keeps an instance out of its app's load-balancing rotation while the
application is not able to serve. This page describes how an app opts into that
and where the verdict comes from.

## Why this exists

A CVM registers with the gateway from `dstack-util setup`, during boot.
`app-compose.service` is ordered *after* `dstack-prepare.service`, so at the
moment of registration the application's containers do not exist yet — the image
may still be pulling. Without a health signal the only thing standing between a
freshly booted instance and a real request is the WireGuard handshake, which
says the tunnel is up and nothing about whether anything is listening behind it.

## Opting in

Health gating is off unless the app asks for it, in `requirements`:

```json
{
  "manifest_version": "3",
  "name": "my-app",
  "runner": "docker-compose",
  "requirements": {
    "health_check": true
  }
}
```

That flag reaches the gateway at registration. An app that does not set it is
never polled and is routed to exactly as it was before this feature existed.

It lives under `requirements` rather than at the top level for a reason:
`requirements` is rejected by guest images older than `manifest_version` 3, and
unknown fields *inside* it are a hard error. So a deployment that asks for
health gating does not silently land on an image that would ignore it.

That protection is conditional, and the condition is yours: write
`"manifest_version": "3"` — **the string form**, as above. `AppCompose` itself
is not `deny_unknown_fields`, so an app-compose left at `"manifest_version": 2`
with a `requirements` block is *rejected* by a current guest and *silently
accepted, minus the requirements*, by an older one. The string form is what an
older guest chokes on.

## Where the verdict comes from

The guest agent recomputes a verdict every 5 seconds and caches it; the gateway
polls `/prpc/v1/Health`, which only reads that cache. The two cadences are
independent on purpose — a fleet of gateway nodes polling the same instance must
not multiply into that many container-runtime queries inside the CVM, and the
RPC is served on the CVM's publicly reachable listener.

An app that never set `health_check` has no verdict to read: the agent runs no
monitor for it, and `/prpc/v1/Health` answers `healthy: true` with an empty
`unhealthy` to whoever asks. No gateway asks, so this only matters to a third
party calling the RPC directly — and there, `true` means "this app opted out of
health gating", not "the agent checked and the app is serving".

There are two sources, and the app picks one.

### Default: container healthchecks

With no `health_status_file`, the agent judges the app's own Compose project:

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

If containers are running but **not one of them declares a healthcheck**, the
instance reports unhealthy rather than healthy. You asked for traffic to be
gated on an answer that nothing can produce, and reporting a pass would leave
you with a feature that is switched on and doing nothing, visible only as the
absence of an effect. Note that this is judged from what the runtime did, not
from your compose file — a `HEALTHCHECK` in a Dockerfile counts, a `healthcheck`
merged in from a YAML anchor counts, and `healthcheck: {disable: true}` does
not, whatever the file appears to say.

A container that declares a healthcheck and is **not running** is not healthy
either, whatever verdict the runtime last recorded for it. Docker re-marks a
stopped container `unhealthy`; nerdctl leaves the last result in place, so a
container that passed one check and then crashed still reports `healthy` with
`Running: false`.

Finding **no containers at all** is not healthy either. A runtime that answers
while having nothing to show means Compose has not got as far as creating
anything.

Only the app's own Compose project is judged, matched on the
`com.docker.compose.project` label. Container state lives on the persistent data
disk and outlives reboots and upgrades, so without that filter one exited
container left behind by an earlier deployment under a different project name
would hold the instance out of rotation permanently.

The `nerdctl-compose` runner needs **nerdctl >= 2.3.1** for Compose
`healthcheck:` to be honoured; earlier versions parse the field and discard it.
Container presence is still detected on older versions, so the boot-window gate
works regardless.

### `health_status_file`: the app answers for itself

For the `bash` runner there are no containers to inspect, and an app may anyway
want to give one whole-application answer rather than have every container
judged separately. Name a file and the agent reads it:

```json
{
  "requirements": {
    "health_check": true,
    "health_status_file": "/dstack/health"
  }
}
```

The file is two lines:

```text
healthy
1771234567
```

| Line | Meaning |
|---|---|
| 1 | `healthy` or `unhealthy`, case-insensitive |
| 2 | Unix timestamp, in seconds, at which the app wrote the file |

The timestamp is not decoration. A file older than **60 seconds** counts as
unhealthy, which is what turns a wedged app — still running, no longer updating
anything — into a verdict rather than a stale `healthy` that never expires.
Refresh it at least twice per that window; writing it once at startup is a way
to take yourself out of rotation a minute later.

Anything else is not healthy: a missing file, a malformed one, an unparseable
timestamp, or a state word the agent does not recognise. Writing it atomically
(write a temporary file in the same directory, then rename) avoids being judged
on a half-written one.

It must be a **regular file**. A FIFO is refused outright rather than reported
as unhealthy-with-a-reason: opening one with no writer would park a thread of
the agent's blocking pool on every refresh, and those threads are not
reclaimable.

Symlinks *are* followed, including a symlinked parent directory. The path is
measured into the compose hash but what sits at that path at runtime is not, so
this is a read the app can redirect — which buys it nothing, because it already
writes the file and can therefore already lie about its own health. The read is
bounded and the contents are never quoted back.

That last point is deliberate: a verdict names the rule that failed — "line 1 is
neither healthy nor unhealthy" — because the report is served to anonymous
callers and the bytes at that path may not be the bytes the app wrote.

The agent reads the file from the guest rootfs, not from inside any container,
so a container that writes it needs the path bind-mounted in. **Mount the
directory, not the file.** A single-file bind mount pins an inode: a rename
inside the container replaces the container's own directory entry and never
touches the file the agent is reading, so the agent sees the original contents
forever, the timestamp ages past the limit, and the instance goes permanently
unhealthy. With the directory mounted, either write-then-rename or a plain
in-place write works.

Before the first refresh completes, the app reports **not** healthy.
Registration happens long before the application is up, so "not determined yet"
must not read as a pass.

## How the gateway uses it

- Health only gates **app-id** routing. Addressing an instance directly by
  instance id is never gated, so an unhealthy instance stays reachable for
  investigation.
- **If no instance of an app reports healthy, the gateway routes to all of them
  anyway.** Health is inference and can be wrong — a misconfigured probe, an
  agent that died, a whole fleet failing for a reason unrelated to the app.
  Blackholing an app on that basis is worse than sending traffic to instances
  that might be fine. Note the consequence: for a **single-instance** app, or a
  fleet that boots together, this rule routes traffic while every instance is
  still `unknown`. Health gating shifts traffic away from a bad instance; it
  does not hold an app offline until one is good.
- A poll that cannot reach the agent is not immediately a verdict. It takes
  `failure_threshold` consecutive failures to demote an instance, so one dropped
  packet does not eject it. An agent that *answers* "unhealthy" is believed on
  the spot.
- Health is a *per-node observation*. Each gateway node polls for itself and
  does not share the result, the same way each node reads its own WireGuard
  handshakes. The verdict is not persisted: a gateway restart puts every
  instance back at `unknown`, and since that is the whole app at once, the
  fail-open above routes to all of them until the first round of polls answers
  a few seconds later. What *is* stored is the CVM's declaration -- the
  `health_check` field of its `inst/` record -- so a restarted node knows which
  instances to poll before any of them re-register.
- Instances whose WireGuard handshake has gone stale are not polled. They are
  already excluded from routing, and polling them would spend the round's budget
  on CVMs that are gone.

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
failure_threshold = 2
```

`enabled = false` restores the behaviour from before health polling existed:
every instance stays eligible regardless of what it reports. Note what that
looks like from the outside: instances that opted in sit at `unknown` forever,
because nothing will ever poll them, and they are *all in rotation*. The gateway
dashboard labels that case `unknown (gating off)` and reports the switch itself
under **This Node → Health Gating**, so the state is not left to be inferred
from a column that means something different when polling is on.
