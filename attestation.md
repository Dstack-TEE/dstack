# TEE Attestation Guide for dstack Applications

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
    - RTMR3: initrd records dstack App details, including compose hash, instance id, app id, and key provider.

MRTD, RTMR0, RTMR1, and RTMR2 can be pre-calculated from the built image (given CPU+RAM specifications). Compare these with the verified quote's MRs to confirm correct base image code execution.

RTMR3 differs as it contains runtime information like compose hash and instance id. Verify this by replaying the event log - if the calculated RTMR3 matches the quote's RTMR3, the event log information is valid. Then verify the compose hash, key provider, and other event log details match expectations.

### 2.2. Determining expected MRs
MRTD, RTMR0, RTMR1, and RTMR2 correspond to the image. dstack OS builds all related software from source.
Build version v0.4.0 using these commands:
```bash
git clone https://github.com/Dstack-TEE/meta-dstack.git
cd meta-dstack/
git checkout 15189bcb5397083b5c650a438243ce3f29e705f4
git submodule update --init --recursive
cd repro-build && ./repro-build.sh -n
```

The resulting dstack-v0.4.0.tar.gz contains:

- ovmf.fd: virtual firmware
- bzImage: kernel image
- initramfs.cpio.gz: initrd
- rootfs.cpio: root filesystem
- metadata.json: image metadata, including kernel boot cmdline

Calculate image MRs using [dstack-mr](https://github.com/kvinwang/dstack-mr):
```bash
dstack-mr -cpu 4 -ram 4096 -metadata dstack-v0.4.0/metadata.json
```

Once these verification steps are completed successfully, the report_data contained in the verified quote can be considered authentic and trustworthy.

## Conclusion

To verify dstack App data trustworthiness:

- Review source code for correctness and safety.
- Build image from source.
- Calculate MRTD, RTMR0, RTMR1, and RTMR2 values using [dstack-mr](https://github.com/kvinwang/dstack-mr).
- Verify quote measurements:
    - Confirm MRTD, RTMR0, RTMR1, and RTMR2 match pre-calculated values.
    - Verify RTMR3 matches the event log replay result.
    - Confirm event log details (compose hash, instance id, app id, rootfs hash, key provider) match expectations.
