# Hardware enablement

Use this page to prepare a bare-metal host before running the [self-hosted quick onboarding guide](./onboarding.md).

dstack does not enable confidential-computing hardware by itself. The host firmware, kernel, device nodes, and QEMU build must already support the target platform.

## Intel TDX hosts

Use the [Canonical TDX setup guide](https://github.com/canonical/tdx) for Ubuntu hosts. The Canonical guide covers supported processors, host OS setup, BIOS settings, reboot, and host verification.

For dstack, the host must have:

- Intel TDX enabled in firmware and the host OS.
- SGX enabled in firmware and exposed to Linux.
- A TDX-capable QEMU available at `/usr/bin/qemu-system-x86_64`.
- SGX device nodes for the local key provider:
  - `/dev/sgx_enclave`
  - `/dev/sgx_provision`

Check the host after you complete the platform setup:

```bash
sudo dmesg | grep -i tdx
test -e /dev/sgx_enclave && test -e /dev/sgx_provision
/usr/bin/qemu-system-x86_64 --version
```

The Canonical guide's TDX verification expects `dmesg` to show that the TDX module initialized. If the SGX device nodes are missing, `dstackup install` cannot start the default local key provider.

Do not install a generic QEMU package as a substitute for TDX host setup. Use the QEMU and kernel stack from your TDX host enablement path.

## AMD SEV-SNP hosts

Use your vendor or distribution's SEV-SNP enablement path. The [AMDSEV project](https://github.com/AMDESE/AMDSEV) documents CPU, BIOS, firmware, kernel, QEMU, OVMF, and verification requirements for SEV-SNP hosts. Confidential Containers also keeps platform setup separate from its [quickstart](https://github.com/confidential-containers/documentation/blob/main/quickstart.md) and points SEV users to AMD host preparation from its [SEV guide](https://github.com/confidential-containers/documentation/blob/main/guides/sev.md).

For dstack, the host must have:

- AMD SEV-SNP enabled in firmware and the host OS.
- `/dev/sev` exposed to Linux.
- A QEMU and OVMF stack that supports SEV-SNP.

Check the host after you complete the platform setup:

```bash
test -e /dev/sev
sudo dmesg | grep -e SEV-SNP -e RMP
cat /sys/module/kvm_amd/parameters/sev_snp
```

The AMDSEV verification path expects `dmesg` to show SEV-SNP and RMP initialization, and `sev_snp` to read `Y`.

Host enablement is necessary but not sufficient for onboarding with KMS. The selected guest image must also contain `digest.sev.txt`, which `dstackup install` uses to pin apps to the measured SNP OS image.

## What dstackup checks

`dstackup install` does a local platform preflight before it writes host config:

- For TDX, it checks the SGX device nodes used by the local key provider.
- For AMD SEV-SNP, it checks `/dev/sev`.

These checks catch missing runtime devices. They do not replace the host enablement process above.
