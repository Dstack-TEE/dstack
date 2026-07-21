# Verity data volumes

A verity volume is a read-only filesystem image protected by dm-verity. The host
attaches untrusted bytes; the guest mounts them only when they match the root
hash measured in `app-compose.json`.

## Disk format

A built volume is a raw GPT image:

```text
p1: DSTACK_VOLUME metadata envelope
p2: filesystem data
p3: dm-verity superblock and hash tree
```

The envelope identifies a candidate disk. It is not trusted. The guest passes
the root from the measured app compose to `veritysetup`, so a forged envelope or
partition table cannot substitute different contents.

## Build

Pack a directory as a reproducible squashfs volume:

```bash
dstack verity --dir ./models -o models.img
```

Or wrap an existing filesystem image:

```bash
dstack verity --fs-image ./models.ext4 -o models.img
```

The command prints the root and a deploy argument. Place the image in the VMM's
configured `cvm.volumes_dir`, then deploy it by bare file name, root, and guest
mount point:

```bash
dstack deploy -c docker-compose.yaml \
  --volume models.img:a1b2c3d4...:/run/models
```

This adds the following measured entry to `app-compose.json`:

```json
{
  "verity_volumes": [
    {
      "source": "models.img",
      "verity_root": "a1b2c3d4...",
      "target": "/run/models"
    }
  ]
}
```

The target must be an absolute path on a writable guest filesystem, such as
`/run` or the app data disk. The guest root filesystem itself is read-only.

## Guest activation

Before the application starts, `dstack-volume mount-all app-compose.json`:

1. Scans `/sys/class/block` for disks whose first partition, or whole disk when
   unpartitioned, starts with the `DSTACK_VOLUME` magic.
2. Matches the full root advertised by the envelope against the measured root.
3. Opens p2 and p3 with `veritysetup` using the measured root.
4. Reads the first mapped block to force an initial integrity check.
5. Mounts the mapped filesystem read-only at the measured target.

A required volume that is missing, malformed, or fails verification stops guest
preparation. dm-verity continues verifying blocks lazily as the application
reads them.

For diagnostics, `dstack-volume scan` lists recognized disks and
`dstack-volume status app-compose.json` compares requested roots with attached
and active devices. A single entry can be activated with
`dstack-volume mount app-compose.json INDEX`.

## Trust and limitations

The root hash authenticates bytes, not availability. A malicious host can omit a
volume or cause I/O failures, but cannot silently replace its contents. Volumes
are unencrypted and are intended for public, shareable data; confidential data
requires a separate encryption design.
