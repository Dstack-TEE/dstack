# Intel TDX Attestation Guide for dstack Applications

This document outlines the process of verifying the authenticity and integrity of data produced by dstack Applications running within Intel TDX environments.

## 1. Review code safety

- Review the Application code to ensure its logic is correct.
- Review the App Compose file to confirm it uses the specified source code or its compiled outputs.
- Review the runtime environment codebase, including virtual firmware, linux kernel, initrd, and rootfs. Verify the correctness of each component.

## 2. Validate data origin authenticity
### 2.1 Understanding tdx quote measurements

Applications generate a tdx quote using dstack's API given the data they want to prove.

The quote signature can be verified using dcap-qvl to confirm its generation by a legitimate TDX CVM and environment trustworthiness.
Following signature verification, examine MRTD and RTMRs to confirm the CVM is executing the verified code.

The MR register values indicate the following:

- MRTD: Contains the virtual firmware measurement, taken by TDX-module in SEAM mode. Virtual firmware (OVMF in dstack's case) is the first code executed post-CVM startup, serving as the App code's trust anchor. Intel signs and guarantees TDX-module integrity.

- RTMR: Measurements recorded by code executing within the CVM. In dstack OS, these measurements are defined as:

    - RTMR0: OVMF records CVM's virtual hardware setup, including CPU count, memory size, and device configuration. While dstack uses fixed devices, CPU and memory specifications can vary. RTMR0 can be computed from these specifications.
    - RTMR1: OVMF records the Linux kernel measurement.
    - RTMR2: Linux kernel records kernel cmdline (including rootfs hash) and initrd measurements.
    - RTMR3: initrd records dstack App details, including compose hash, GPU policy and attestation events, instance id, app id, and key provider.

MRTD, RTMR0, RTMR1, and RTMR2 can be pre-calculated from the built image (given CPU+RAM specifications). Compare these with the verified quote's MRs to confirm correct base image code execution.

RTMR3 differs as it contains runtime information like compose hash and instance id. Verify this by replaying the event log - if the calculated RTMR3 matches the quote's RTMR3, the event log information is valid. Then verify the compose hash, key provider, and other event log details match expectations.

After `compose-hash`, each configured init script produces an ordered
`init-script-hash` event whose payload is the SHA-256 digest of the exact UTF-8
script bytes. The event order matches the script array order. These events let
an infrastructure provider contribute initialization code approved by
multiple parties and let each party verify its code independently without
reconstructing the complete compose document.

For a GPU launch, any `init-script-hash` events are followed by
`gpu-policy-hash` and, after successful NVIDIA attestation and policy
evaluation, `gpu-attestation`. The `gpu-policy-hash` payload is
`SHA-256(JCS(requirements.gpu_policy))`, using `{}` when the field is omitted.
The `gpu-attestation` payload is JSON containing the verified device count,
CC/DevTools state, and `evidence_sha256`.

The guest-agent `GpuInfo` API returns the complete `nvattest` JSON captured during boot; `Attest` returns the same bytes in `boottime_gpu_evidence` when called with `include_boottime_gpu_evidence`, so a verifier can fetch the quote and the GPU evidence in one round trip. It is not trustworthy by itself. After verifying the TDX quote and replaying the event log to RTMR3, hash the exact UTF-8 bytes of `GpuInfo.attestation` (or `Attest.boottime_gpu_evidence`) and require the result to equal the `gpu-attestation` event's `evidence_sha256`. See [GPU Security for AI Workloads](./security/security-model.md#gpu-security-for-ai-workloads) for the event schema, ordering, Rego example, and platform differences.

### 2.2. Determining expected MRs
MRTD, RTMR0, RTMR1, and RTMR2 correspond to the image. dstack OS builds all related software from source.
Build the exact image revision you intend to verify. See
[Build the dstack guest OS](./building-guest-os.md) for prerequisites and the
reproducible build workflow. At a high level:

```bash
git clone https://github.com/Dstack-TEE/dstack.git
cd dstack
git checkout <release-revision>
make os-image
```

The resulting `dstack-<version>.tar.gz` contains:

- ovmf.fd: virtual firmware
- bzImage: kernel image
- initramfs.cpio.gz: initrd
- rootfs.img.parted.verity: partitioned dm-verity root filesystem
- metadata.json: image metadata, including kernel boot cmdline

Calculate image MRs using [dstack-mr](../dstack/dstack-mr/):
```bash
VERSION=0.6.0 # replace with the image version being verified
cargo run --manifest-path dstack/Cargo.toml --bin dstack-mr measure \
  -c 4 -m 4G "dstack-$VERSION/metadata.json"
```

Once these verification steps are completed successfully, the report_data contained in the verified quote can be considered authentic and trustworthy.

## Conclusion

To verify dstack App data trustworthiness:

- Review source code for correctness and safety.
- Build image from source.
- Calculate MRTD, RTMR0, RTMR1, and RTMR2 values using [dstack-mr](https://github.com/Dstack-TEE/dstack/tree/next/dstack/dstack-mr).
- Verify quote measurements:
    - Confirm MRTD, RTMR0, RTMR1, and RTMR2 match pre-calculated values.
    - Verify RTMR3 matches the event log replay result.
    - Confirm event log details (compose hash, instance id, app id, rootfs hash, key provider) match expectations.
