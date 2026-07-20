# Develop with dstack without TEE hardware

Development guest images can run dstack's normal guest setup on a KVM machine
that has no TDX or SEV-SNP support. The VMM starts the guest with `no_tee`, the
guest supplies the TDX ABI through `dstack-tee-simulator`, and `swtpm` provides
persistent TPM-backed application keys. This is suitable for development and
integration testing, not for production workloads or secrets.

## What this mode tests

The development simulator provides configfs-tsm reports, RTMR extension files,
and a CCEL event log. Guest preparation, measurements, application key setup,
encrypted persistent storage, the guest agent, and Docker Compose therefore
use their normal code paths.

It does not provide hardware isolation or a valid hardware-signed quote. The
host controls QEMU and swtpm, and a production verifier or KMS must reject the
simulated quote.

## Build the development image on the host

TEE hardware is not needed for the build. Follow the prerequisites in
[Build the dstack guest OS](building-guest-os.md), then run this from the
repository root:

```bash
make os-deps
cd os/yocto/repro-build
RELEASE_FLAVORS="dev" ./repro-build.sh -n
```

The artifact used below is
`os/yocto/repro-build/dist/dstack-dev-<version>.tar.gz`. Confirm that it really
is a development image:

```bash
mkdir -p ~/.dstack-vmm/image
tar -xzf os/yocto/repro-build/dist/dstack-dev-*.tar.gz \
  -C ~/.dstack-vmm/image
jq '{version, git_revision, is_dev}' \
  ~/.dstack-vmm/image/dstack-dev-*/metadata.json
```

Expected output includes `"is_dev": true`. Use a development image for this
workflow because production images do not include `dstack-tee-simulator`.

## Install and configure the VMM

Install QEMU and swtpm on the development host. On Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y qemu-system-x86 swtpm swtpm-tools jq
test -r /dev/kvm && test -w /dev/kvm
```

Add the current user to the `kvm` group and log in again if the `/dev/kvm`
check fails because of its permissions.

Build the VMM and supervisor from the same checkout as the image:

```bash
cargo build --manifest-path dstack/Cargo.toml --release \
  -p dstack-vmm -p supervisor
```

Install both binaries and the CLI on the machine that will run QEMU. You can
also run them directly from the checkout during development:

```bash
mkdir -p ~/.dstack-vmm
install -Dm755 dstack/target/release/dstack-vmm ~/.local/bin/dstack-vmm
install -Dm755 dstack/target/release/supervisor ~/.local/bin/supervisor
install -Dm755 dstack/vmm/src/vmm-cli.py ~/.local/bin/dstack
mkdir -p ~/.dstack-vmm
cp dstack/vmm/vmm.toml ~/.dstack-vmm/vmm.toml
```

Set these values in `~/.dstack-vmm/vmm.toml`:

```toml
[image]
path = "/home/USER/.dstack-vmm/image"

[cvm]
qemu_path = "/usr/bin/qemu-system-x86_64"

[cvm.networking]
mode = "user"

[supervisor]
exe = "/home/USER/.local/bin/supervisor"
```

Start the VMM from a stable working directory because its default API socket is
relative to that directory:

```bash
mkdir -p ~/.dstack-vmm/run
cd ~/.dstack-vmm/run
dstack-vmm -c ../vmm.toml
```

In another terminal, check that the development image is visible:

```bash
cd ~/.dstack-vmm/run
dstack lsimage --json | jq '.[] | {name, version, is_dev}'
```

## Launch with no TEE and swtpm

Create a small stateful workload:

```yaml
# docker-compose.yml
services:
  state-test:
    image: alpine:3.20
    command:
      - sh
      - -c
      - |
        date -Iseconds >> /data/boots
        touch /data/persistent-marker
        sleep infinity
    volumes:
      - state-data:/data
volumes:
  state-data: {}
```

Convert it to app-compose JSON and select the TPM key provider:

```bash
dstack compose \
  --name swtpm-persistence \
  --docker-compose docker-compose.yml \
  --key-provider tpm \
  --public-logs \
  --public-sysinfo \
  --output app-compose.json
```

Deploy with the development image, no KMS, and no TEE:

```bash
dstack deploy \
  --name swtpm-persistence \
  --image dstack-dev-<version> \
  --compose app-compose.json \
  --vcpu 2 --memory 3G --disk 10G \
  --no-tee
```

Successful output contains a VM ID. `dstack info VM_ID` should eventually show
`Boot Progress: done`. The QEMU command line should contain the swtpm frontend
and no TDX guest object:

```bash
ps aux | grep '[q]emu-system' | grep -E -- '-tpmdev|tpm-tis'
ps aux | grep '[s]wtpm socket'
```

The VMM stores both durable components below the VM work directory:

```text
~/.dstack-vmm/vm/VM_ID/hda.img
~/.dstack-vmm/vm/VM_ID/swtpm/tpm2-00.permall
```

Do not delete either path if the VM must restart with the same state.

## Verify encrypted storage and restart persistence

First check the guest preparation log:

```bash
dstack logs VM_ID -n 300 | grep -E \
  'Generating app keys from TPM|Filesystem options|LUKS2 header|Device mapper'
```

A successful first boot includes output like:

```text
Generating app keys from TPM
Filesystem options: encryption=true, filesystem=Zfs
Mounting tmpfs for in-memory LUKS header
Loading the LUKS2 header
Device mapper /dev/mapper/dstack_data_disk is ready
```

Record the instance ID, then perform a graceful restart:

```bash
dstack info VM_ID | grep 'Instance ID'
dstack stop VM_ID
dstack start VM_ID
```

Wait for `Boot Progress: done`, then inspect the recent events and boot log:

```bash
dstack info VM_ID
dstack logs VM_ID -n 300 | grep -E \
  'mounting data disk|Loading the LUKS2 header|Device mapper|Container .* Started'
```

The restart passes when all of the following hold:

1. the instance ID is unchanged;
2. the event stream says `mounting data disk`, not `initializing data disk`;
3. the LUKS mapping becomes ready without reformatting the disk;
4. Docker starts the existing container and volume, and
   `/data/persistent-marker` and the earlier entries in `/data/boots` remain.

## Common failures

`tpm key provider requested but swtpm is not installed` means `swtpm` is not on
the VMM user's `PATH`. If QEMU reports that KVM is unavailable, confirm that
hardware virtualization is enabled and that `/dev/kvm` is writable by the VMM
user.
