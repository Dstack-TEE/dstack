# Unified dstack rootfs image
# Use DSTACK_FLAVOR (via multiconfig) to select variant:
#   prod, dev

# Default flavor settings (can be overridden by multiconfig)
DSTACK_FLAVOR ?= "prod"
DSTACK_DEV ?= "0"

# Base configuration
include dstack-rootfs-base.inc

# Production or development mode
include ${@'dstack-rootfs-dev.inc' if d.getVar('DSTACK_DEV') == '1' else 'dstack-rootfs-prod.inc'}

# NVIDIA support is included in all images; services are gated at runtime by
# hardware-detection ExecCondition= checks so the same image works without GPUs.
include dstack-rootfs-nvidia.inc
