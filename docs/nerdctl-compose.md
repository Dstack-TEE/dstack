# nerdctl Compose and lazy image pulling

dstack supports two independent Compose runners. The runner is part of
`app-compose.json`, so it is included in the compose hash and attestation.

| `runner` | Image manager | `snapshotter` support |
|---|---|---|
| `docker-compose` | Docker Engine | none (Docker's overlayfs store) |
| `nerdctl-compose` | containerd | `overlayfs` or `stargz` |

## Deploy with stargz

Build and push an eStargz image before deployment. For example, with Buildx:

```bash
docker buildx build -t registry.example.com/example/app:estargz \
  --output type=registry,oci-mediatypes=true,compression=estargz,force-compression=true \
  .
```

Reference that image from `docker-compose.yaml`, then deploy it with:

```bash
dstack deploy -c docker-compose.yaml \
  --runner nerdctl-compose \
  --snapshotter stargz
```

The resulting application manifest contains:

```json
{
  "manifest_version": "3",
  "runner": "nerdctl-compose",
  "snapshotter": "stargz"
}
```

Use containerd without lazy pulling by selecting overlayfs:

```bash
dstack deploy -c docker-compose.yaml \
  --runner nerdctl-compose \
  --snapshotter overlayfs
```

If `snapshotter` is omitted for `nerdctl-compose`, it defaults to `overlayfs`.
Setting `snapshotter` with `docker-compose` is rejected rather than silently
ignored.

## Compatibility

`nerdctl compose` implements the commonly used Docker Compose features, but it
is not a drop-in implementation of every Docker-specific extension. Test
applications that use Docker socket mounts, custom runtimes, or advanced
networking before switching runners. The `nerdctl-compose` runner requires
pre-built images and rejects Compose `build` sections. This avoids depending
on an in-guest BuildKit daemon and ensures lazy-pull images were converted
before deployment.

Both backends keep their own image and container metadata. Changing the runner
recreates the application through the selected backend; it does not migrate
existing Docker containers into containerd.
