# Legacy direct-QEMU runner

This directory contains the imported direct-QEMU development runner. It is
retained for low-level image debugging; normal deployments should use
`dstack-vmm`, `dstack`, or `dstackup`.

Run it explicitly instead of adding the directory to `PATH`:

```bash
python3 tools/meta-dstack/vm-runner/vm-runner.py --help
```

`enable-vfio-passthrough.sh` is the matching standalone host helper for NVIDIA
GPU/NVSwitch passthrough. The `samples/` directory contains the historical CUDA
notebook workload used with this runner.
