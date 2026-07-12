#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Detecting NVIDIA GPUs and NVSwitches"
mapfile -t GPU_BDFS < <(
  lspci -d 10de: -nn | grep '3D controller' | awk '{print $1}'
)
mapfile -t GPU_DEV_IDS < <(
  lspci -d 10de: -nn | grep '3D controller' | sed -n 's/.*\[10de:\([0-9A-Fa-f]\+\)\].*/\1/p'
)
mapfile -t SW_BDFS < <(
  lspci -d 10de: -nn | grep 'Bridge' | awk '{print $1}'
)
mapfile -t SW_DEV_IDS < <(
  lspci -d 10de: -nn | grep 'Bridge' | sed -n 's/.*\[10de:\([0-9A-Fa-f]\+\)\].*/\1/p'
)

NGPU=${#GPU_BDFS[@]}
NSW=${#SW_BDFS[@]}
TOTAL=$((NGPU+NSW))

if [ $TOTAL -eq 0 ]; then
  echo "No NVIDIA GPUs or NVSwitches found. Exiting."
  exit 1
fi

echo "Found $NGPU GPU(s): ${GPU_BDFS[*]}"
echo "Found $NSW NVSwitch(s): ${SW_BDFS[*]}"

echo "==> Loading VFIO modules"
sudo modprobe vfio vfio_pci

echo "==> Tagging devices for VFIO passthrough"
# GPUs first
for idx in "${!GPU_BDFS[@]}"; do
  BDF=${GPU_BDFS[$idx]}; DEV=${GPU_DEV_IDS[$idx]}
  echo "Tagging GPU $BDF (DevID=10de:$DEV)"
  if ! echo "10de $DEV" | sudo tee /sys/bus/pci/drivers/vfio-pci/new_id > /dev/null; then
    echo "  -> failure, removing and retrying"
    echo "10de $DEV" | sudo tee /sys/bus/pci/drivers/vfio-pci/remove_id > /dev/null || true
    echo "10de $DEV" | sudo tee /sys/bus/pci/drivers/vfio-pci/new_id > /dev/null
  fi
done
# NVSwitches
for idx in "${!SW_BDFS[@]}"; do
  BDF=${SW_BDFS[$idx]}; DEV=${SW_DEV_IDS[$idx]}
  echo "Tagging NVSwitch $BDF (DevID=10de:$DEV)"
  if ! echo "10de $DEV" | sudo tee /sys/bus/pci/drivers/vfio-pci/new_id > /dev/null; then
    echo "  -> failure, removing and retrying"
    echo "10de $DEV" | sudo tee /sys/bus/pci/drivers/vfio-pci/remove_id > /dev/null || true
    echo "10de $DEV" | sudo tee /sys/bus/pci/drivers/vfio-pci/new_id > /dev/null
  fi
done
