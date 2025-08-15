#!/bin/bash

# SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

VMDIR=$1
IMAGE_PATH=./images/$(jq -r '.image' ${VMDIR}/vm-manifest.json)
IMG_METADATA=${IMAGE_PATH}/metadata.json
MEM=$(jq -r '.memory' ${VMDIR}/vm-manifest.json)
VCPUS=$(jq -r '.vcpu' ${VMDIR}/vm-manifest.json)

VDA=${VMDIR}/hda.img

PROCESS_NAME=qemu

INITRD=${IMAGE_PATH}/$(jq -r '.initrd' ${IMG_METADATA})
KERNEL=${IMAGE_PATH}/$(jq -r '.kernel' ${IMG_METADATA})
CDROM=${IMAGE_PATH}/$(jq -r '.rootfs' ${IMG_METADATA})
TDVF_FIRMWARE=${IMAGE_PATH}/$(jq -r '.bios' ${IMG_METADATA})
CMDLINE=$(jq -r '.cmdline' ${IMG_METADATA})
CONFIG_DIR=${VMDIR}/shared
TD=${TD:-1}
RO=${RO:-on}
CID=$(( ( RANDOM % 10000 )  + 3 ))

ARGS="${ARGS} -kernel ${KERNEL}"
ARGS="${ARGS} -initrd ${INITRD}"

echo INITRD=${INITRD}
echo ARGS=${ARGS}
echo VDA=${VDA}
echo CMDLINE=${CMDLINE}
echo TD=${TD}

if [ "${TD}" == "1" ]; then
	MACHINE_ARGS=",confidential-guest-support=tdx,hpet=off"
	PROCESS_NAME=td
	TDX_ARGS="-device vhost-vsock-pci,guest-cid=${CID} -object tdx-guest,id=tdx"
fi
BIOS="-bios ${TDVF_FIRMWARE}"

sleep 2

qemu-system-x86_64 \
		   -accel kvm \
		   -m ${MEM}M -smp ${VCPUS} \
		   -name ${PROCESS_NAME},process=${PROCESS_NAME},debug-threads=on \
		   -cpu host \
		   -machine q35,kernel_irqchip=split${MACHINE_ARGS} \
		   ${BIOS} \
		   ${TDX_ARGS} \
		   -nographic \
		   -nodefaults \
		   -chardev stdio,id=ser0,signal=on -serial chardev:ser0 \
		   -device virtio-net-pci,netdev=nic0_td -netdev user,id=nic0_td \
		   -drive file=${VDA},if=none,id=virtio-disk0 -device virtio-blk-pci,drive=virtio-disk0 \
		   -cdrom ${CDROM} \
		   -virtfs local,path=${CONFIG_DIR},mount_tag=host-shared,readonly=${RO},security_model=mapped,id=virtfs0 \
		   ${ARGS} \
		   -append "${CMDLINE}"
