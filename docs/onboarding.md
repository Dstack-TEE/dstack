# Self-hosted quick onboarding

Use this guide to get a first dstack app running on one Intel TDX host. The workflow uses `dstackup` for host setup and `dstack` for app deployment:

```bash
curl -fsSL https://raw.githubusercontent.com/Dstack-TEE/dstack/master/scripts/install.sh | sh
sudo dstackup install
sudo dstack deploy \
  -n hello-nginx \
  -c /usr/local/share/dstack/examples/hello-nginx/docker-compose.yaml \
  --port 8080:80
curl http://127.0.0.1:8080/
```

AMD SEV-SNP hosts use the same `dstackup` and `dstack` commands after you provide a guest image that contains the SNP image digest (`digest.sev.txt`). As of June 28, 2026, the latest stable CPU image from `meta-dstack` is TDX-pinned only, so the copy-paste path below is not the AMD happy path yet.

For multi-node production, Gateway TLS, custom domains, or on-chain governance, use the full [deployment guide](./deployment.md).

## What this workflow creates

- User commands under `/usr/local/bin`.
- Host daemon binaries under `/usr/local/libexec/dstack`.
- Static assets and examples under `/usr/local/share/dstack`.
- Generated host config under `/etc/dstack`.
- Host state, KMS keys, VMs, and verified guest images under `/var/lib/dstack`.
- Source and build cache under `/var/cache/dstack`.
- Runtime sockets and process state under `/run/dstack`.
- A localhost-only VMM dashboard on port `9080`.
- A local `dstack-auth` webhook and `dstack-vmm` systemd unit.
- A single KMS CVM unless you pass `--no-kms`.
- A direct host port mapping for your app.

## Prerequisites

Run these commands on the self-hosted dstack machine.

- Root or sudo access.
- A TDX host that satisfies [Hardware enablement](./hardware-enablement.md).
- Outbound HTTPS access to GitHub.

If the host is not enabled yet, start with [Hardware enablement](./hardware-enablement.md).

Install the build packages used by the onboarding flow:

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  ca-certificates \
  curl \
  git \
  libssl-dev \
  pkg-config \
  tar
```

Install and start Docker if it is not already available. The default TDX key provider uses Docker. Use your normal Docker installation process, or on Ubuntu:

```bash
sudo apt install -y docker.io docker-compose-v2
sudo systemctl enable --now docker
```

Install Rust and load Cargo into your shell:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
```

Build and install the `dstackup` bootstrap command:

```bash
curl -fsSL https://raw.githubusercontent.com/Dstack-TEE/dstack/master/scripts/install.sh | sh
```

The bootstrap installer builds `dstackup` from a temporary source checkout and installs it under `/usr/local/bin`. The `dstackup install` command then builds and installs `dstack`, `dstack-auth`, `dstack-vmm`, `supervisor`, static assets, and host config into the system layout.

## 1. Install the host stack

Run:

```bash
sudo dstackup install
```

`dstackup install` auto-detects TDX or AMD SEV-SNP. If no local guest image exists, it downloads the latest CPU image from [meta-dstack releases](https://github.com/Dstack-TEE/meta-dstack/releases), requires the release SHA-256 digest by default, verifies the tarball, stages the unpack, and only then adopts the image.

On TDX, `dstackup install` starts the SGX key provider automatically from `/usr/local/share/dstack/key-provider-build`. To use a different provider, pass one of:

```bash
sudo dstackup install --key-provider-src /path/to/key-provider-build
sudo dstackup install --use-existing-key-provider 127.0.0.1:3443
```

On AMD SEV-SNP, no SGX key provider is needed. The selected guest image must include `digest.sev.txt`; otherwise, `dstackup install` fails before it starts the host units because apps could not be pinned to the measured SNP OS image.

To use a GPU image, pull it before install:

```bash
sudo dstackup image pull --gpu
sudo dstackup install
```

If multiple images are present, pass the image name or release version to `--image`, such as `dstack-0.5.11`, `dstack-nvidia-0.5.11`, or `0.5.11`. If the requested release-shaped image is not local, `dstackup install` downloads it.

When install succeeds, it prints the dashboard URL, the KMS address, and a `dstack deploy` command template. The default dashboard URL is:

```text
http://127.0.0.1:9080
```

If you connect from your laptop, open an SSH tunnel first:

```bash
ssh -L 9080:127.0.0.1:9080 <user>@<host>
```

Then open `http://127.0.0.1:9080` locally. `dstackup install --expose` is intentionally disabled until the remote TLS and token transport exists.

## 2. Deploy a first app

Deploy the checked-in nginx example:

```bash
sudo dstack deploy \
  -n hello-nginx \
  -c /usr/local/share/dstack/examples/hello-nginx/docker-compose.yaml \
  --port 8080:80
```

The deploy command:

- converts the Docker Compose file into a dstack app-compose manifest,
- computes the compose hash and app ID,
- uses the VMM endpoint, guest image, and auth allowlist from `dstackup install`,
- registers the compose hash in the single-node auth allowlist,
- creates the CVM with the default app resources of 2 vCPU, 2048 MB memory, and 20 GB disk, and
- maps `http://127.0.0.1:8080/` on the host to port `80` in the CVM.

Pass `--vcpu`, `--memory`, or `--disk` to change the app resources before you deploy.

The `--port 8080:80` mapping means `host_port:vm_port` and uses TCP on `127.0.0.1`. The full accepted forms are `vm`, `host:vm`, `proto:host:vm`, and `proto:addr:host:vm`. Use `tcp` or `udp` for `proto`. Fixed host and VM ports must be between 1 and 65535. If you omit the host port, or use `auto` or `0`, `dstack` picks a free localhost port and prints the selected mapping after deploy.

Open the app from the host:

```bash
curl http://127.0.0.1:8080/
```

If you are connecting from your laptop, tunnel the app port too:

```bash
ssh -L 8080:127.0.0.1:8080 <user>@<host>
```

## Common operations

Check deployed apps:

```bash
dstack apps
```

Show recent app logs:

```bash
dstack logs <vm-id>
```

`dstack apps` and `dstack logs` read the VMM endpoint from the local `dstackup install` state, so they work with the default localhost dashboard endpoint. For a custom prefix, pass the same `--prefix` you used for install.

Remove a local image:

```bash
sudo dstackup image rm <image-name>
```

List local images:

```bash
sudo dstackup image list
```

Tear down the host units and KMS CVM:

```bash
sudo dstackup destroy
```

Add `--purge` only when you also want to delete generated config, state, cached source, runtime files, and KMS keys for that install. For a custom `--prefix`, purge also removes dstack-owned installed files under that prefix.

## Install with a custom prefix

Use `--prefix` when you want a second isolated install on the same host. A custom prefix relocates the install layout under that directory:

| Purpose | Example path for `--prefix /opt/dstack-test` |
| --- | --- |
| User commands | `/opt/dstack-test/bin` |
| Host daemons | `/opt/dstack-test/libexec/dstack` |
| Static assets | `/opt/dstack-test/share/dstack` |
| Config | `/opt/dstack-test/etc/dstack` |
| State and images | `/opt/dstack-test/var/lib/dstack` |
| Source and build cache | `/opt/dstack-test/var/cache/dstack` |
| Runtime files | `/opt/dstack-test/run/dstack` |

Install `dstackup` into the prefix, then use the same prefix for `dstackup` and `dstack`:

```bash
curl -fsSL https://raw.githubusercontent.com/Dstack-TEE/dstack/master/scripts/install.sh | sh -s -- --prefix /opt/dstack-test

sudo /opt/dstack-test/bin/dstackup install \
  --prefix /opt/dstack-test \
  --dashboard-port 19080 \
  --auth-port 18001 \
  --host-api-port 10001

sudo /opt/dstack-test/bin/dstack \
  --prefix /opt/dstack-test \
  deploy \
  -n hello-nginx \
  -c /opt/dstack-test/share/dstack/examples/hello-nginx/docker-compose.yaml \
  --port 18080:80
```

For a custom prefix, `dstackup` derives distinct systemd unit names from the prefix unless you pass `--instance`. You still need distinct TCP and vsock ports for each running install.

Remove a custom-prefix install with the same prefix:

```bash
sudo /opt/dstack-test/bin/dstackup destroy --prefix /opt/dstack-test --purge
```

## Security boundaries

This onboarding path is designed for one operator on one host.

- The VMM dashboard and management API bind to `127.0.0.1` by default. Use SSH tunneling for remote access.
- `dstackup install` pins the app OS image hash from the selected guest image (`digest.txt` for TDX, `digest.sev.txt` for SEV-SNP). If the digest cannot be read, install fails unless you pass `--allow-unpinned-image`.
- `dstack deploy` registers the app compose hash in the local auth allowlist from `dstackup install`. Without that allowlist update, a KMS-mode app can boot but will not receive keys.
- Gateway is not part of this flow. Apps are exposed through direct host port mappings.

Use the [deployment guide](./deployment.md) when you need domain routing, Gateway certificates, on-chain authorization, KMS replicas, or multi-node operation.

## Troubleshooting

### Image download fails

`dstackup install` downloads the latest CPU image when KMS mode needs an image and none exists locally. If the download fails, check network access to GitHub and the meta-dstack release:

```bash
sudo dstackup image pull
```

If a release does not publish a SHA-256 digest, `dstackup image pull` and `dstackup install` fail before unpacking it. Use `--insecure` only when you intentionally accept an unverified image download.

If you use a custom prefix or image directory, pass the same `--prefix` or `--image-path` to `install` and `image` commands.

### Missing `digest.sev.txt` on AMD SEV-SNP

TDX images pin apps with `digest.txt`. AMD SEV-SNP images pin apps with `digest.sev.txt`. If the selected image does not contain `digest.sev.txt`, install fails with:

```text
no os-image pin: could not read digest.sev.txt
```

Use `--image` or `--image-path` with an SNP-capable image that contains `digest.sev.txt`. Do not use `--allow-unpinned-image` for onboarding unless you intentionally want apps to boot without OS-image pinning.

### No key provider on TDX

TDX uses an SGX-backed key provider for KMS sealing. `dstackup install` uses the installed key provider assets by default. To override that, pass one of:

```bash
sudo dstackup install --use-existing-key-provider 127.0.0.1:3443
sudo dstackup install --key-provider-src /path/to/key-provider-build
```

AMD SEV-SNP does not use this key provider.

### Port already in use

Move the conflicting port explicitly:

```bash
sudo dstackup install --dashboard-port 19080 --auth-port 18001 --host-api-port 10001
```

For app ports, change the `--port` mapping:

```bash
sudo dstack deploy \
  -c /usr/local/share/dstack/examples/hello-nginx/docker-compose.yaml \
  --port 18080:80
```

### KMS bootstrap does not finish

Check the VMM service and the KMS CVM logs:

```bash
sudo journalctl -u dstack-vmm -n 200 --no-pager
dstack logs <kms-vm-id>
```

The KMS VM ID is printed by `dstackup install` when it creates or reuses the KMS CVM.
