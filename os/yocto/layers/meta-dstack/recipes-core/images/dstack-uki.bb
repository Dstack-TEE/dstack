# Unified Kernel Image (UKI) for dstack
#
# This recipe generates a UKI containing kernel, initramfs, and cmdline
# with dm-verity root hash for GCP deployment.

SUMMARY = "dstack Unified Kernel Image"
LICENSE = "MIT"

DEPENDS = "systemd-boot systemd-boot-native virtual/kernel python3-pefile-native"

inherit image-artifact-names
require conf/image-uefi.conf

# Initramfs settings
INITRAMFS_IMAGE = "dstack-initramfs"
INITRAMFS_FSTYPES = "cpio.gz"

# Kernel settings
KERNEL_IMAGETYPE = "bzImage"

# Base kernel cmdline (verity hash added dynamically)
UKI_CMDLINE_BASE = "console=ttyS0 init=/init panic=1 net.ifnames=0 biosdevname=0 \
mce=off oops=panic pci=noearly pci=nommconf random.trust_cpu=y random.trust_bootloader=n \
tsc=reliable no-kvmclock"

# Flavor settings (should match dstack-rootfs.bb, set via multiconfig)
DSTACK_FLAVOR ?= "prod"

# Verity image to get hash from - always use dstack-rootfs (same PN, different multiconfig)
VERITY_IMAGE = "dstack-rootfs"
VERITY_TYPE = "squashfs"

UKI_FILENAME = "dstack-uki.efi"

do_configure[noexec] = "1"
do_compile[noexec] = "1"
do_install[noexec] = "1"

# Dependencies
do_uki[depends] += "systemd-boot:do_deploy virtual/kernel:do_deploy"
do_uki[depends] += "${INITRAMFS_IMAGE}:do_image_complete"
do_uki[depends] += "${VERITY_IMAGE}:do_image_complete"
do_uki[depends] += "systemd-boot-native:do_populate_sysroot python3-pefile-native:do_populate_sysroot"

python do_uki() {
    import os
    import bb.process

    deploy_dir = d.getVar('DEPLOY_DIR_IMAGE')
    target_arch = d.getVar('EFI_ARCH')

    # Find the EFI stub
    stub = os.path.join(deploy_dir, f"linux{target_arch}.efi.stub")
    if not os.path.exists(stub):
        bb.fatal(f"EFI stub not found: {stub}")

    # Find kernel
    kernel = os.path.join(deploy_dir, d.getVar('KERNEL_IMAGETYPE'))
    if not os.path.exists(kernel):
        bb.fatal(f"Kernel not found: {kernel}")

    # Find initramfs
    initramfs_image = d.getVar('INITRAMFS_IMAGE')
    machine = d.getVar('MACHINE')
    initramfs_fstypes = d.getVar('INITRAMFS_FSTYPES')
    initrd = os.path.join(deploy_dir, f"{initramfs_image}-{machine}.{initramfs_fstypes}")
    if not os.path.exists(initrd):
        bb.fatal(f"Initramfs not found: {initrd}")

    # Read verity hash
    staging_verity_dir = d.getVar('STAGING_VERITY_DIR') or d.expand('${TMPDIR}/work-shared/${MACHINE}/dm-verity')
    verity_image = d.getVar('VERITY_IMAGE')
    verity_type = d.getVar('VERITY_TYPE')
    verity_env = os.path.join(staging_verity_dir, f"{verity_image}.{verity_type}.verity.env")

    root_hash = ""
    data_size = ""

    if os.path.exists(verity_env):
        with open(verity_env, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('ROOT_HASH='):
                    root_hash = line.split('=', 1)[1]
                elif line.startswith('DATA_SIZE='):
                    data_size = line.split('=', 1)[1]
        bb.note(f"Read verity env: root_hash={root_hash}, data_size={data_size}")
    else:
        bb.fatal(f"Verity env file not found: {verity_env}")

    if not root_hash or not data_size:
        bb.fatal(f"ROOT_HASH/DATA_SIZE missing from verity env: {verity_env}")

    # Build cmdline
    cmdline_base = d.getVar('UKI_CMDLINE_BASE')
    cmdline = f"{cmdline_base} dstack.rootfs_hash={root_hash} dstack.rootfs_size={data_size}"
    bb.note(f"UKI cmdline: {cmdline}")

    # Output path
    output = os.path.join(deploy_dir, d.getVar('UKI_FILENAME'))

    # Build ukify command with proper Python paths
    native_sysroot = d.getVar('RECIPE_SYSROOT_NATIVE')
    staging_libdir = d.getVar('STAGING_LIBDIR_NATIVE')

    # Find Python version directory for native packages (version-agnostic)
    import glob
    _pyglob = sorted(glob.glob(os.path.join(staging_libdir, 'python3.*', 'site-packages')))
    python_sitepackages = _pyglob[-1] if _pyglob else os.path.join(staging_libdir, 'python3', 'site-packages')

    # Set environment for ukify
    env = os.environ.copy()
    env['PYTHONPATH'] = python_sitepackages

    ukify_path = os.path.join(native_sysroot, 'usr', 'bin', 'ukify')
    # Pass an argument list (no shell) so values like cmdline don't need quoting
    # and can't be split/expanded by the shell.
    ukify_cmd = [
        ukify_path, "build",
        f"--efi-arch={target_arch}",
        f"--stub={stub}",
        f"--linux={kernel}",
        f"--initrd={initrd}",
        f"--cmdline={cmdline}",
        f"--tools={native_sysroot}/usr/lib/systemd/tools",
        f"--output={output}",
    ]

    bb.note(f"Running: {' '.join(ukify_cmd)}")
    bb.note(f"PYTHONPATH: {python_sitepackages}")

    import subprocess
    result = subprocess.run(ukify_cmd, capture_output=True, text=True, env=env)
    if result.stdout:
        bb.note(result.stdout)
    if result.stderr:
        bb.note(result.stderr)
    if result.returncode != 0:
        bb.fatal(f"ukify failed with exit code {result.returncode}")

    bb.note(f"UKI created: {output}")
}

addtask uki before do_build
