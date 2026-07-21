# Verity Volumes: pre-seeding images and data into a CVM

Starting a CVM is slow mostly because of image *extraction*: decompressing layers and writing millions of files onto the encrypted disk. On one pinned vCPU this dominates — about 30 s for a 3.3 GB image, ~2 min for 7 GB, with a hard ~15 s decompress floor no amount of storage tuning beats. Download is the smaller cost.

A verity volume removes it. It's a read-only, dm-verity-protected disk, built once, that a CVM mounts and uses as-is. The layers on it are already extracted, so the CVM does no pull and no extraction — it mounts the volume and verifies blocks lazily as the app reads them. One volume can back many CVMs at once.

The build tool (`dstack verity`) and the in-guest seeding are implemented and validated end to end ([What's proven](#whats-proven)).

## The shape of it

A volume has a **root hash** — its identity and integrity check — and a **target** that says what it's for:

- `"docker"` — the volume is a docker overlay2 store; its images are seeded into docker as cache hits.
- `"/some/path"` — the volume's filesystem is mounted there, for data like model weights.

On disk, a volume is a raw GPT image with three partitions:

```
p1: DSTACK_VOLUME metadata envelope
p2: filesystem data
p3: dm-verity superblock + hash tree
```

The guest finds disks by the `DSTACK_VOLUME` magic in `p1`, then opens `p2` as the verity data device and `p3` as the verity hash device. That keeps the verity layer independent of the filesystem format: the guest does not need to read a squashfs/ext4 superblock to find a hash offset.

An app lists its volumes in `app-compose.json`. dstack already hashes that file into the app's identity, so every root hash is measured as part of `app_id`, and the CVM only uses content matching what it was attested as. Everything else is untrusted: the host hands over bytes, and dm-verity rejects any that don't match the root.

A volume is *additive* — it only adds read-only lower layers, so anything not on one is pulled normally — and *fail-safe*: a missing or mismatched volume falls back to a pull.

## What a user writes

The `docker-compose.yaml` is unchanged (pin images by digest so the measured identity binds the exact bytes):

A data volume's mount point must be on a writable filesystem — the guest rootfs is read-only, so use `/run/...` (a writable tmpfs) or the app's data disk, not an arbitrary top-level path like `/models`:

```yaml
services:
  vllm:
    image: vllm/vllm-openai@sha256:abc123...           # from the "docker" volume
    command: ["--model", "/run/models/llama-70b"]
    volumes:
      - /run/models/llama-70b:/run/models/llama-70b:ro # from the data volume
```

Each volume is one `verity_volumes` entry in the measured `app-compose.json`:

```json
"verity_volumes": [
  { "verity_root": "115b6877...", "target": "docker" },
  { "verity_root": "a1b2c3d4...", "target": "/run/models/llama-70b" }
]
```

You don't hand-write that with the `dstack` CLI — `dstack deploy --volume` generates it (below). Build volumes with `dstack verity`, which prints the exact `--volume` spec to paste:

```bash
dstack verity vllm/vllm-openai@sha256:abc123...   # -> --volume vllm.img:115b6877...:docker
dstack verity --dir ./llama-70b-weights/          # -> --volume llama-70b.img:a1b2c3d4...:/run/models/llama-70b
dstack verity --fs-image ./weights.ext4           # -> wrap an existing filesystem image
```

It needs no docker daemon, no CVM, and no TDX. For images it pulls the pinned layers from the registry and lays out the docker store itself; for `--dir` it packs the directory as squashfs; for `--fs-image` it treats the supplied filesystem image as opaque bytes and only wraps it in verity/GPT. Either way it writes one volume file. Pass several images to pack them into a single `docker` volume; shared base layers are stored once. There is no auto-detection: a volume contains whatever you built it from, and the compose names those images normally.

This covers both cases. Several volumes in one CVM (the image *and* the model) is several entries with different targets. Several images from one volume is a single `docker` volume built from all of them, listed as one entry, with the compose unchanged. Attach order does not matter ([Delivery](#delivery)).

## Trust

`verity_root` lives in `app-compose.json`, so it's part of the hash that becomes `app_id` (see [Normalized App Compose](./normalized-app-compose.md)), and it is enforced by dm-verity. The consumer trusts the root hash, not whoever built the volume. A host that tampers with the bytes causes a verity fault, not a silent swap, so the delivery path can stay untrusted.

`dstack verity` is deterministic: the same pinned image digests always produce the same `verity_root`, bit-for-bit (canonical overlay2 layout with chain-id cache-ids; a fixed timestamp and salt; UUIDs derived from the packed bytes/root hash; a deterministic GPT wrapper). One caveat: the squashfs layout is produced by `mksquashfs`, so a verifier must use a `squashfs-tools` version that lays out bytes identically (recent versions are stable; the build records nothing about the tool version yet). A verifier can therefore recompute the root from the digest-pinned images and confirm the volume is those images, without trusting whoever ran the build. The build needs no docker daemon and no TEE, so it can also run in a CI job that attests it (see [Reproducible builds and provenance](#reproducible-builds-and-provenance)); the two checks are independent. Turning on a volume changes `app-compose.json` and thus `app_id`, which is correct: the volume is part of the measured configuration.

## How docker seeding works

A `docker` volume is a squashfs filesystem holding a docker overlay2 store, which has two very different halves:

```
image/overlay2/       metadata: image configs, layer db, tags   (KB to a few MB)
overlay2/<id>/diff/   the already-extracted layer files          (the GBs)
```

`diff/` is the layer already decompressed and untarred. Seeding reuses it in place:

1. Open the volume with veritysetup (`p2` as data, `p3` as hash) and mount it read-only at a writable path (`/run/dstack-verity`). The rootfs is read-only dm-verity, so the mountpoint has to be on a writable fs; squashfs itself mounts read-only directly, no journal and nothing to replay.
2. Copy the metadata (a few MB) into `/var/lib/docker`.
3. Per layer: make a writable `overlay2/<id>/` dir, copy its handful of tiny files, and bind-mount only the big `diff/` read-only from the volume.
4. This runs from `dstack-prepare.sh` *before* dockerd starts, so there's no restart — dockerd comes up with every image on the volume already present.

The layer dir stays writable because docker writes a `committed` marker into it on first use; only `diff/` underneath is read-only. (Bind-mounting the whole dir read-only is the one thing that breaks container creation.)

squashfs is used, rather than ext4, for two reasons: the dstack guest kernel mounts it (it's the guest's own rootfs — erofs, the other obvious candidate, isn't compiled in), and `mksquashfs` with a pinned timestamp is byte-reproducible with no extra work, where ext4 needs its wall-clock superblock and inode times patched out. It's built fully uncompressed, so there's no decompression at read time either — the point was to remove extraction, not move it.

At run time the container's overlay uses the verity-backed `diff/`s as lower layers and a fresh writable upper on the encrypted disk. Reads are verified per block on first touch, then cached; nothing is decompressed or written. This is where the ~1 s start comes from instead of 30 s–2 min. A data volume is simpler: open, mount at the path, and the container bind-mounts it — no unpacking.

## Delivery

The volume *file* and the deploy request travel separately. First set `cvm.volumes_dir` in the host's `vmm.toml` (it's empty by default, which disables volume attachment). The operator then places the built file in that `volumes_dir` (however they like — copy, object store, shared mount), and deploy references it by bare file name:

```bash
dstack deploy -c docker-compose.yaml \
  --volume vllm.img:115b6877...:docker \
  --volume llama-70b.img:a1b2c3d4...:/run/models/llama-70b
```

Each `--volume NAME:VERITY_ROOT:TARGET` both attaches the file and writes the measured `verity_volumes` entry (the root is yours to supply, from `dstack verity`, so it stays part of `app_id`). `vmm-cli.py` takes the same file with a hand-authored `app-compose.json` instead. The vmm resolves each name against `volumes_dir` (rejecting anything with a path separator) and attaches it as a read-only virtio-blk device, `--volume` carries only the name and read-only flag, never the bytes; the bytes are already on the host. Disks are still attached in any order. The Rust guest helper scans each whole disk: when the kernel exposes partitions it checks partition 1, otherwise it checks the start of the raw disk. A matching `DSTACK_VOLUME` envelope supplies a kind and the full claimed root. For the verity kind, the guest opens partitions 2 and 3 only after matching that root against the measured compose. The envelope and partition table are untrusted hints; the guest passes the measured root to dm-verity, so tampering causes a verity fault rather than a wrong mount. Integrity is checked lazily, per block on first read. Read-only plus content-addressed means one physical copy serves every CVM that references it: a base image or model shared by a hundred replicas is built, stored, and extracted once.

## Building volumes

`dstack verity` builds the store from scratch, without a docker daemon and without a CVM — just the registry (a `docker` volume does need root, because laying out overlay2 whiteouts uses `mknod` and a `trusted.*` xattr; a `--dir` or `--fs-image` volume needs no root). It pulls each layer by digest, and lays out the overlay2 store the way docker would, with one deliberate change: the per-layer directory id is the layer's *chain-id* instead of docker's random cache-id. That's what makes the store a pure function of the image. AUFS `.wh.` whiteouts in the layer tars are converted to their overlay2 on-disk form (a `0:0` char device, or the `trusted.overlay.opaque` xattr) so deletions in upper layers still take effect. Then `mksquashfs` packs it with a fixed timestamp, `veritysetup` builds a separate hash image with a fixed salt and a UUID derived from the filesystem bytes, and the builder wraps both blobs in a deterministic GPT disk (`p1` volume metadata, `p2` data, `p3` verity metadata/hash tree). A `--dir` volume skips the overlay2 layout and pull entirely — it packs the directory straight into the same partitioned squashfs + verity format. A `--fs-image` volume skips `mksquashfs` too: the supplied ext4/xfs/etc. image becomes `p2` after 4096-byte padding, so the guest only needs kernel support and suitable read-only mount behavior for that filesystem.

With those fixed, two runs of the same digests produce the same bytes. The build needs no daemon and no TEE, so it can run in a CI job that also attests it (below).

### Reproducible builds and provenance

Because the root is a deterministic function of the pinned image digests, a verifier has two independent checks:

- **Reproducibility** — recompute the root from the digests and check it matches `app-compose.json`. This needs nothing but the digests and does not trust the builder.
- **Provenance** — run `verity` in CI and attest the output with [SLSA build provenance](https://github.com/actions/attest-build-provenance) / Sigstore. This ties the root to a specific workflow and inputs.

Either alone is sufficient; they can be used together. In your own app repo — using an installed `dstack` (verity volumes aren't tied to the dstack source tree):

```yaml
# .github/workflows/build-verity-volume.yml
permissions: { id-token: write, attestations: write, contents: read }
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - run: sudo apt-get install -y squashfs-tools cryptsetup-bin
      - run: sudo dstack verity "$IMAGE" -o volume.img --json | tee out.json
      - uses: actions/attest-build-provenance@v2
        with: { subject-path: volume.img }
```

(`sudo` because the docker-store layout needs `mknod` + a `trusted.*` xattr.)

## What this doesn't do yet

- Images should be pinned by digest; a mutable tag doesn't bind the bytes (a digest pin is verified against the fetched manifest, so a swapped registry response is caught).
- `verity` reads gzip and uncompressed layers; zstd-compressed layers are not handled yet (it fails rather than producing a wrong store).
- The compose must reference an image the same way it was passed to `verity`. Docker-Hub names are normalized to their canonical form (`docker.io/library/<name>`), so a bare `alpine` and `docker.io/library/alpine` match; a private-registry reference must match verbatim.
- A data volume's `target` is a mount point, and must be on a writable filesystem in the guest (e.g. under `/run`, or the app's data disk) — the rootfs is read-only dm-verity, so an arbitrary top-level path can't be created. A missing/unwritable target is skipped, fail-safe.
- A `docker` volume is architecture-specific. `--platform` selects it (default `linux/amd64`, matching today's Intel TDX guests); an arm64 confidential host (NVIDIA Vera, AWS Graviton/Nitro) needs `linux/arm64`. dm-verity checks bytes, not architecture, so a wrong-arch volume whose root you pinned still opens and seeds — the container then fails to exec (wrong-arch binaries), it isn't caught up front. Match `--platform` to the guest; recording the platform in the volume and checking it in the guest is a follow-up.
- Layers are treated as public — the volume is unencrypted and shareable. Secret layers would need a per-app, KMS-encrypted volume, and that's out of scope for now.
- Under TDX the single-copy saving is on storage, transfer, and extraction, not RAM — each CVM still caches the blocks it reads in its own encrypted memory.
- The per-boot `docker image prune -af` removes images no running container references, so bake the images your compose actually runs; guarding prune against verity-seeded images is a follow-up.
- Verity volumes require a guest image that ships `/bin/dstack-volume`; the Rust helper runs from `dstack-prepare.sh` before dockerd starts.
- Seeded overlay2 metadata lives on the persistent disk, while the layer `diff/` binds are re-established each boot. A *partial* seed (a metadata copy fails mid-write) unwinds its binds and falls back to a normal pull. The open gap is across boots: if a volume that seeded once is later not re-attached (or swapped), its metadata persists while its `diff/` binds don't, so docker can see the image present with empty layers. The normal reboot (same volume) re-binds correctly. Reconciling stale seeded metadata against missing binds on boot is a follow-up — it needs image→layer dependency walking so it doesn't drop a pulled image that happens to share a base layer.

## What's proven

The whole path ran on Intel TDX with no change to the guest OS image — only a host-side change to attach the disk. A fresh CVM — different app, empty image list, never having pulled the image — attached a pre-built volume read-only, matched it by root hash, mounted it, and seeded docker. The image was present with no pull and no extraction: essentially nothing was written to the CVM's disk during seeding (an extraction would write gigabytes), seeding took about a second, and the container ran in about a second — versus 30 s to 2 min to pull and extract. That confirms a fresh CVM gets an image purely from a read-only attested volume, and that unrelated images still pull.

The build side is proven too. `dstack verity` builds a volume daemonlessly and is byte-for-byte reproducible: independent runs of the same pinned image produce the same volume and the same `verity_root`, including a multi-layer image with whiteouts. The resulting store loads and runs in a stock docker with no pull, and the overlay2 whiteouts apply correctly (deleted files stay deleted). The filesystem choice was checked against the live guest kernel: it mounts uncompressed squashfs and reads it back correctly; erofs is not compiled in.

## Open questions

Whether the guest-agent should handle `verity_volumes` natively instead of through a pre-launch helper; how the operator garbage-collects stale volumes and tracks roots across image updates; how volume files are distributed to hosts at scale (`--volume` references a name already in `volumes_dir`); and encrypted volumes for secret layers.
