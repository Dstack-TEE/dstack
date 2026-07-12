#!/usr/bin/env python3

import argparse
import json
import logging
import os
import random
import re
import string
import subprocess
import uuid
import configparser
import host_api
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from functools import reduce

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def generate_config_paths():
    paths = [
        "/etc/dstack/client.conf",
        os.path.expanduser("~/.config/dstack/client.conf"),
    ]
    current_dir = os.getcwd()
    while current_dir != "/":
        paths.append(os.path.join(current_dir, ".dstack", "client.conf"))
        current_dir = os.path.dirname(current_dir)
    return paths


def merge2(a, b):
    if isinstance(a, dict) and isinstance(b, dict):
        c = a.copy()
        for k, v in b.items():
            c[k] = merge2(a.get(k), v)
        return c
    if b is None:
        return a
    return b


def test_merge2():
    assert merge2({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}
    assert merge2({"a": 1}, {"a": 2}) == {"a": 2}
    assert merge2({"a": {"b": 1}}, {"a": {"c": 2}}) == {"a": {"b": 1, "c": 2}}


def merge_dicts(*dicts):
    return reduce(merge2, dicts, {})


def test_merge_dicts():
    assert merge_dicts({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}
    assert merge_dicts({"a": 1}, {"a": 2}) == {"a": 2}
    assert merge_dicts({"a": {"b": 1}}, {"a": {"c": 2}}) == {
        "a": {"b": 1, "c": 2}}
    assert merge_dicts({"a": {"b": 1}}, {"a": {"b": 2}}) == {"a": {"b": 2}}
    assert merge_dicts({"a": {"b": 1}}, {"a": {"b": 2}, "c": 3}) == {
        "a": {"b": 2}, "c": 3}
    assert merge_dicts({"a": 1}, {"b": 2}, {"c": 3}) == {
        "a": 1, "b": 2, "c": 3}
    assert merge_dicts({"a": 1}, {"a": 2}, {"c": 3}) == {"a": 2, "c": 3}


def round_up(value, multiple):
    """
    Round up a value to the nearest multiple of another value.
    If the value is already a multiple, it remains unchanged.

    Args:
        value (int): The value to round up
        multiple (int): The multiple to round up to

    Returns:
        int: The rounded up value
    """
    if multiple <= 1:
        return value

    remainder = value % multiple
    if remainder == 0:
        return value

    return value + (multiple - remainder)


def ini_to_dict(filename):
    config = configparser.ConfigParser()
    config.read(filename)

    result = {}
    for section in config.sections():
        result[section] = {}
        for key, value in config.items(section):
            result[section][key] = value
    return result


def load_configs_merged(config_paths):
    config = {}
    for config_path in config_paths:
        if os.path.exists(config_path):
            logger.info(f"Loading configuration from {config_path}")
            config = merge_dicts(config, ini_to_dict(config_path))
    return config


def update_guest_config(config_file: str, data: Dict):
    if not os.path.exists(config_file):
        config = {}
    else:
        with open(config_file, 'r') as f:
            config = json.load(f)
    config.update(data)
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)


def gen_vm_config(vm_dir, host_port, manifest=None, os_image_hash=None):
    shared_dir = os.path.join(vm_dir, 'shared')
    for filename in ['config.json', '.sys-config.json']:
        config_file = os.path.join(shared_dir, filename)
        update_guest_config(config_file, {
            "host_api_url": f"http://10.0.2.2:{host_port}/api",
            "host_vsock_port": host_port
        })
        if manifest:
            update_guest_config(config_file, {
                "vm_config": json.dumps({
                    "os_image_hash": os_image_hash,
                    "cpu_count": manifest['vcpu'],
                    "memory_size": manifest['memory'] * 1024 * 1024
                })
            })


@dataclass
class DstackConfig:
    """Configuration for dstack client."""
    docker_registry: Optional[str] = None
    default_image_name: str = ''
    qemu_path: str = 'qemu-system-x86_64'

    @classmethod
    def load(cls) -> 'DstackConfig':
        """Load configuration from file."""
        cfgs = load_configs_merged(generate_config_paths())

        def cfg_get(section, key, fallback):
            if section in cfgs and key in cfgs[section]:
                return cfgs[section][key]
            return fallback
        me = cls()
        me.docker_registry = cfg_get('docker', 'registry', cls.docker_registry)
        me.default_image_name = cfg_get(
            'image', 'default', cls.default_image_name)
        me.qemu_path = cfg_get('qemu', 'path', cls.qemu_path)
        return me


class DstackManager:
    def __init__(self):
        self.run_path = os.path.abspath(os.getenv('RUN_PATH', './vms'))
        self.config = DstackConfig.load()

    def _generate_instance_id(self) -> str:
        """Generate a random instance ID."""
        return str(uuid.uuid4())

    def _read_compose_file(self, compose_file: str) -> str:
        """Read and validate compose file."""
        if not os.path.isfile(compose_file):
            raise FileNotFoundError(f"Compose file not found: {compose_file}")
        with open(compose_file, 'r') as f:
            return f.read()

    def _create_directories(self, work_dir: str) -> tuple[str, str]:
        """Create necessary directories."""
        if os.path.exists(work_dir):
            raise FileExistsError(f"The instance already exists at {work_dir}")

        shared_dir = os.path.join(work_dir, 'shared')
        certs_dir = os.path.join(shared_dir, 'certs')
        os.makedirs(shared_dir, exist_ok=True)
        os.makedirs(certs_dir, exist_ok=True)
        return shared_dir, certs_dir

    def _convert_memory_to_mb(self, memory: str) -> int:
        """Convert memory string to MB."""
        if memory.upper().endswith('T'):
            return int(memory[:-1]) * 1024 * 1024
        if memory.upper().endswith('G'):
            return int(memory[:-1]) * 1024
        if memory.upper().endswith('M'):
            return int(memory[:-1])
        return int(memory)

    def _parse_port_mapping(self, port_str: str) -> dict:
        """Parse port mapping string in format 'protocol[:address]:from:to'."""
        try:
            parts = port_str.split(':')
            if len(parts) == 3:
                proto, from_port, to_port = parts
                address = "127.0.0.1"  # default to localhost
            elif len(parts) == 4:
                proto, address, from_port, to_port = parts
            else:
                raise ValueError(
                    "Invalid port mapping format. Use 'protocol[:address]:from:to'")

            return {
                "address": address,
                "protocol": proto.lower(),
                "from": int(from_port),
                "to": int(to_port)
            }
        except ValueError as e:
            raise ValueError(f"Invalid port mapping '{port_str}': {str(e)}")

    def setup_instance(self, args: argparse.Namespace) -> None:
        """Set up a new instance with the provided configuration."""
        try:
            # Generate instance ID if work_dir not provided
            instance_id = os.path.basename(
                args.dir) if args.dir else self._generate_instance_id()
            work_dir = args.dir or os.path.join(self.run_path, instance_id)

            # Create directories
            shared_dir, certs_dir = self._create_directories(work_dir)

            # Read compose file
            compose_content = self._read_compose_file(args.compose_file)

            # Create app-compose.json
            app_compose = {
                "manifest_version": 1,
                "name": "example",
                "version": "1.0.0",
                "features": [],
                "runner": "docker-compose",
                "docker_compose_file": compose_content,
                "local_key_provider_enabled": args.local_key_provider,
                "secure_time": False,
            }
            with open(os.path.join(shared_dir, 'app-compose.json'), 'w') as f:
                json.dump(app_compose, f, indent=4)
            # Read image metadata and create config.json

            if self.config.docker_registry:
                update_guest_config(os.path.join(shared_dir, '.sys-config.json'), {
                    "docker_registry": self.config.docker_registry,
                })

            # Create VM manifest
            memory = self._convert_memory_to_mb(str(args.memory))
            disk_size = self._convert_memory_to_mb(str(args.disk)) // 1024
            port_map = []
            if args.port:
                for port_str in args.port:
                    port_map.append(self._parse_port_mapping(port_str))

            if args.gpu == ['all']:
                gpus = {
                    "attach_mode": "all",
                }
            elif args.gpu == ['none'] or not args.gpu:
                gpus = {
                    "attach_mode": "listed",
                    "gpus": []
                }
            else:
                gpus = {
                    "attach_mode": "listed",
                    "gpus": [
                        {"slot": gpu} for gpu in args.gpu
                    ]
                }
            gpus = self.resolve_gpus(gpus)
            vm_config = {
                "id": instance_id,
                "name": "",
                "vcpu": args.vcpus,
                "gpus": gpus,
                "memory": memory,
                "disk_size": disk_size,
                "image_path": args.image,
                "image": os.path.basename(args.image.rstrip('/')),
                "port_map": port_map,
                "pin_numa": args.pin_numa,
                "hugepages": args.hugepages,
                "created_at_ms": int(datetime.now().timestamp() * 1000)
            }
            with open(os.path.join(work_dir, 'vm-manifest.json'), 'w') as f:
                json.dump(vm_config, f, indent=4)
            logger.info(f"Work directory prepared successfully at: {work_dir}")

        except Exception as e:
            logger.error(f"Failed to setup instance: {str(e)}")
            raise

    @staticmethod
    def collect_all_gpus() -> dict:
        """Collect available NVIDIA GPUs and NVSwitches."""
        try:
            # Find all NVIDIA GPUs (3D controllers)
            gpu_cmd = subprocess.run(
                ['lspci', '-d', '10de:', '-nn'],
                capture_output=True, text=True, check=True
            )
            gpu_output = gpu_cmd.stdout.strip()

            gpus = []
            bridges = []

            # Process each line of output
            for line in gpu_output.split('\n'):
                if not line.strip():
                    continue

                slot = line.split()[0]  # Bus:Device.Function

                # Extract device ID from the line
                match = re.search(r'\[10de:([0-9A-Fa-f]+)\]', line)
                if not match:
                    continue
                # Check if it's a GPU (3D controller) or NVSwitch (Bridge)
                if '3D controller' in line:
                    gpus.append({
                        "slot": slot,
                    })
                elif 'Bridge' in line:
                    bridges.append({
                        "slot": slot,
                    })

            logger.info(
                f"Found {len(gpus)} GPU(s) and {len(bridges)} NVSwitch(es)")

            return {
                "attach_mode": "all",
                "gpus": gpus,
                "bridges": bridges
            }
        except subprocess.SubprocessError as e:
            logger.warning(f"Failed to collect GPU information: {str(e)}")
            return {
                "attach_mode": "all",
                "gpus": [],
                "bridges": []
            }

    @staticmethod
    def resolve_gpus(gpus: dict) -> dict:
        """Resolve GPU slots."""
        match gpus['attach_mode']:
            case 'listed':
                return gpus
            case 'all':
                return DstackManager.collect_all_gpus()
            case _:
                raise ValueError(
                    f"Invalid GPU attach mode: {gpus['attach_mode']}")

    def run_instance(self, vm_dir: str, host_port: int, imgdir: Optional[str] = None, dry_run: bool = False) -> None:
        """Run a VM instance from the specified directory.

        Args:
            vm_dir: Directory containing the VM configuration
            dry_run: Whether to run in dry run mode
        """

        manifest_path = os.path.join(vm_dir, 'vm-manifest.json')
        if not os.path.exists(manifest_path):
            raise ValueError(f"VM manifest not found in {vm_dir}")

        with open(manifest_path, 'r') as f:
            manifest = json.load(f)

        if dry_run:
            print("Manifest:")
            print(json.dumps(manifest, indent=4))

        # Get image path and metadata
        image_path = manifest.get('image_path') or os.path.join(
            imgdir, manifest['image'])
        img_metadata_path = os.path.join(image_path, 'metadata.json')

        if not os.path.exists(img_metadata_path):
            raise ValueError(
                f"Image metadata not found at {img_metadata_path}")

        with open(img_metadata_path, 'r') as f:
            img_metadata = json.load(f)

        os_image_hash = open(os.path.join(
            image_path, 'digest.txt'), 'r').read().strip()
        gen_vm_config(vm_dir, host_port, manifest, os_image_hash)

        mem_gb = manifest['memory'] // 1024
        vcpu_count = manifest['vcpu']
        disk_size = manifest['disk_size']

        vda = os.path.join(vm_dir, 'hda.img')
        config_dir = os.path.join(vm_dir, 'shared')

        # Create disk if it doesn't exist
        if not os.path.exists(vda):
            subprocess.run(['qemu-img', 'create', '-f', 'qcow2',
                           vda, f"{disk_size}G"], check=True)

        cid = random.randint(1, 10000) + 3

        # Prepare QEMU command
        cmd_args = []
        rootfs_image = os.path.join(image_path, img_metadata['rootfs'])
        if rootfs_image.endswith('.img.verity'):
            cmd_args.extend([
                '-drive', f'file={rootfs_image},if=none,id=virtio-disk0,format=raw',
                '-device', 'virtio-blk-pci,drive=virtio-disk0',
            ])
        elif rootfs_image.endswith('.img'):
            cmd_args.extend(['-cdrom', rootfs_image])
        else:
            raise ValueError(
                f"Unsupported rootfs image format: {rootfs_image}")
        cmd_args.extend(['-drive', f'file={vda},if=none,id=virtio-disk1'])
        cmd_args.extend(['-device', 'virtio-blk-pci,drive=virtio-disk1'])

        # Add network configuration
        port_args = []
        for port_map in manifest.get('port_map', []):
            protocol = port_map.get('protocol', 'tcp')
            bind_address = port_map.get('address', '127.0.0.1')
            host_port = port_map['from']
            vm_port = port_map['to']
            port_args.append(
                f"hostfwd={protocol}:{bind_address}:{host_port}-:{vm_port}")
        cmd_args.extend([
            '-device', 'virtio-net-pci,netdev=nic0_td',
            '-netdev', f"user,id=nic0_td{','+','.join(port_args) if len(port_args) > 0 else ''}"
        ])

        # Handle GPUs
        gpus_cfg = manifest.get('gpus') or {}
        gpus = gpus_cfg.get('gpus') or []
        bridges = gpus_cfg.get('bridges') or []
        dev_num = 1
        hugepages = manifest.get('hugepages', False)
        if hugepages:
            numa_nodes = {}
            if gpus:
                for dev in gpus:
                    node = numa_node_of_device(dev['slot'])
                    if node not in numa_nodes:
                        numa_nodes[node] = 0
                    numa_nodes[node] += 1
            else:
                numa_nodes[0] = 0
            n_numa = len(numa_nodes)
            # Round up cpu cores and memory to multiple times of numa nodes
            vcpu_count = round_up(vcpu_count, n_numa)
            mem_gb = round_up(mem_gb, n_numa)
            vcpu_per_node = vcpu_count // n_numa
            mem_per_node = mem_gb // n_numa

            bus_nr = 5
            for ind, (node, count) in enumerate(numa_nodes.items()):
                cmd_args.extend([
                    '-numa', f'node,nodeid={ind},cpus={ind * vcpu_per_node}-{(ind + 1) * vcpu_per_node - 1},memdev=mem{ind}',
                    '-object', f'memory-backend-file,id=mem{ind},size={mem_per_node}G,mem-path=/dev/hugepages,share=on,prealloc=yes,host-nodes={node},policy=bind',
                    '-device', f'pxb-pcie,id=pcie.node{node},bus=pcie.0,addr={0xa + ind},numa_node={ind},bus_nr={bus_nr}'
                ])
                bus_nr += count + 1
        if gpus:
            cmd_args.extend(['-object', 'iommufd,id=iommufd0'])
            if not hugepages:
                for dev in gpus:
                    slot = dev['slot']
                    cmd_args.extend([
                        '-device', f'pcie-root-port,id=pci.{dev_num},bus=pcie.0,chassis={dev_num}',
                        '-device', f'vfio-pci,host={slot},bus=pci.{dev_num},iommufd=iommufd0',
                    ])
                    dev_num += 1
            else:
                for dev in gpus:
                    slot = dev['slot']
                    node = numa_node_of_device(slot)
                    cmd_args.extend([
                        '-device', f'pcie-root-port,id=pci.{dev_num},bus=pcie.node{node},chassis={dev_num}',
                        '-device', f'vfio-pci,host={slot},bus=pci.{dev_num},iommufd=iommufd0',
                    ])
                    dev_num += 1
            for bridge in bridges:
                slot = bridge['slot']
                cmd_args.extend([
                    '-device', f'pcie-root-port,id=pci.{dev_num},bus=pcie.0,chassis={dev_num}',
                    '-device', f'vfio-pci,host={slot},bus=pci.{dev_num},iommufd=iommufd0',
                ])
                dev_num += 1
        # Add kernel command line
        cmd_args.extend(['-append', img_metadata['cmdline']])

        base_args = [
            self.config.qemu_path,
            '-accel', 'kvm',
            '-m', f'{mem_gb}G',
            '-smp', str(vcpu_count),
            '-cpu', 'host',
            '-machine', 'q35,kernel_irqchip=split,confidential-guest-support=tdx,hpet=off',
            '-object', 'tdx-guest,id=tdx',
            '-nographic',
            '-nodefaults',
            '-chardev', 'stdio,id=ser0,signal=on',
            '-serial', 'chardev:ser0',
            '-kernel', os.path.join(image_path, img_metadata['kernel']),
            '-initrd', os.path.join(image_path, img_metadata['initrd']),
            '-bios', os.path.join(image_path, img_metadata['bios']),
            '-virtfs', f'local,path={config_dir},mount_tag=host-shared,readonly=off,security_model=mapped,id=virtfs0',
            '-device', f'vhost-vsock-pci,guest-cid={cid}',
        ]

        pin_numa = manifest.get('pin_numa', False)
        if pin_numa:
            if gpus:
                numa_node = numa_node_of_device(gpus[0]['slot'])
            else:
                numa_node = 0
            cpus = open(
                f'/sys/devices/system/node/node{numa_node}/cpulist').read().strip()
            base_args = ['taskset', '-c', cpus] + base_args
        cmd = base_args + cmd_args
        print(" \n".join(cmd))
        if dry_run:
            return
        # Run the command
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to start VM: {e}")


def numa_node_of_device(pci_slot):
    """
    Get the NUMA node associated with a PCI device.

    Args:
        pci_slot (str): PCI slot in format "domain:bus:device.function" (e.g., "0000:ab:00.0")

    Returns:
        int: NUMA node number, or -1 if device doesn't exist or has no NUMA affinity
    """
    # Normalize the PCI slot format if needed
    if not pci_slot.startswith("0000:"):
        pci_slot = f"0000:{pci_slot}"
    # Try to read NUMA node from sysfs
    numa_path = f"/sys/bus/pci/devices/{pci_slot}/numa_node"

    with open(numa_path, 'r') as f:
        numa_node = int(f.read().strip())
        return numa_node


def list_available_gpus() -> None:
    """List available NVIDIA GPUs."""
    try:
        # Run lspci with verbose output to get detailed information
        result = subprocess.run(
            ['lspci', '-vvk'], capture_output=True, text=True)
        output_lines = result.stdout.split('\n')

        # Find all GPU entries and their details
        gpu_blocks = []
        current_block = []
        in_gpu_block = False

        for line in output_lines:
            if 'NVIDIA' in line and '3D controller' in line:
                # Start of a new GPU block
                if current_block:
                    gpu_blocks.append(current_block)
                current_block = [line]
                in_gpu_block = True
            elif in_gpu_block:
                if line.strip() == '' or (line[0] != '\t' and line[0] != ' ' and len(current_block) > 1):
                    # End of the current block
                    gpu_blocks.append(current_block)
                    current_block = []
                    in_gpu_block = False
                else:
                    # Continue adding lines to the current block
                    current_block.append(line)

        # Add the last block if it exists
        if current_block:
            gpu_blocks.append(current_block)

        if gpu_blocks:
            print("\nAvailable GPU IDs:")
            print("ID   Numa Node  In Use    Description")
            print("-------------------------------------")

            for block in gpu_blocks:
                # Extract device ID from the first line
                device_id = block[0].split()[0]
                description = block[0].split(':', 2)[2].strip()

                # Check if GPU is in use by examining Control line and Latency
                in_use = False
                for line in block:
                    if 'Control:' in line and 'I/O+' in line and 'BusMaster+' in line:
                        in_use = True
                    elif 'Latency:' in line:
                        in_use = True

                status = "Yes" if in_use else "No"
                node = numa_node_of_device(device_id)
                print(f"{device_id}   {node}   {status:8}  {description}")
            print()
    except subprocess.SubprocessError as e:
        logger.warning(f"Could not list GPU devices: {str(e)}")


def start_server(dir: str, kp_port: int):
    config = host_api.ServerConfig(
        vm_dir=dir, kp_address="127.0.0.1", kp_port=kp_port)
    api, host_port = host_api.create_http_server(config)
    print(f"Starting HTTP server on localhost:{host_port}")
    thread = threading.Thread(target=api.serve_forever, daemon=True)
    thread.host_port = host_port
    thread.start()
    return thread


def tag_vfio():
    """
    Tag NVIDIA GPUs and NVSwitches for VFIO passthrough.
    Detects NVIDIA devices and configures them for VFIO passthrough.
    """
    logging.info("==> Detecting NVIDIA GPUs and NVSwitches")

    try:
        # Use a more structured approach to detect devices
        devices = detect_nvidia_devices()

        if not devices['gpus'] and not devices['switches']:
            logging.error("No NVIDIA GPUs or NVSwitches found. Exiting.")
            return

        ngpu = len(devices['gpus'])
        nsw = len(devices['switches'])

        logging.info(f"Found {ngpu} GPU(s)")
        logging.info(f"Found {nsw} NVSwitch(es)")

        # Load VFIO modules
        logging.info("==> Loading VFIO modules")
        load_vfio_modules()

        # Tag devices for VFIO passthrough
        logging.info("==> Tagging devices for VFIO passthrough")

        # Deduplicate device IDs
        unique_dev_ids = {}
        for device_type, device_list in devices.items():
            device_name = "GPU" if device_type == "gpus" else "NVSwitch"
            for device in device_list:
                dev_id = device['dev_id']
                if dev_id not in unique_dev_ids:
                    unique_dev_ids[dev_id] = device_name
                # If the device ID is already in the dict but with a different type,
                # we'll keep the original type for simplicity

        # Process unique device IDs
        for dev_id, device_name in unique_dev_ids.items():
            tag_device_for_vfio(dev_id, device_name)

        logging.info("VFIO passthrough setup complete")

    except Exception as e:
        logging.error(f"Failed to enable VFIO passthrough: {e}")


def detect_nvidia_devices():
    """
    Detect NVIDIA GPUs and NVSwitches in the system.

    Returns:
        dict: Dictionary with 'gpus' and 'switches' keys, each containing a list of
              dictionaries with 'dev_id' for each device.
    """
    devices = {
        'gpus': [],
        'switches': []
    }

    try:
        # Run lspci once and parse the output
        lspci_output = subprocess.check_output(
            "lspci -d 10de: -nn",
            shell=True, text=True
        ).strip().split('\n')

        for line in lspci_output:
            if not line:
                continue

            # Extract Device ID
            dev_id_match = re.search(r'\[10de:([0-9A-Fa-f]+)\]', line)
            if not dev_id_match:
                continue

            dev_id = dev_id_match.group(1)

            # Categorize device
            if '3D controller' in line:
                devices['gpus'].append({'dev_id': dev_id})
            elif 'Bridge' in line:
                devices['switches'].append({'dev_id': dev_id})

    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to detect NVIDIA devices: {e}")

    return devices


def load_vfio_modules():
    """
    Load the VFIO kernel modules required for device passthrough.
    Assumes the script is run with appropriate permissions.

    Raises:
        RuntimeError: If modules cannot be loaded
    """
    try:
        subprocess.run(["modprobe", "vfio"], check=True)
        subprocess.run(["modprobe", "vfio_pci"], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to load VFIO modules: {e}")
        raise RuntimeError("Failed to load VFIO modules") from e


def tag_device_for_vfio(dev_id, device_type):
    """
    Tag a PCI device for VFIO passthrough.

    Args:
        dev_id (str): Device ID
        device_type (str): Type of device (GPU or NVSwitch)
    """
    logging.info(f"Tagging {device_type} (DevID=10de:{dev_id})")

    new_id_path = "/sys/bus/pci/drivers/vfio-pci/new_id"
    remove_id_path = "/sys/bus/pci/drivers/vfio-pci/remove_id"
    device_id_value = f"10de {dev_id}"

    try:
        # Directly write to the sysfs file
        write_to_sysfs(new_id_path, device_id_value)
    except Exception:
        try:
            # Remove the ID first in case it's already there
            try:
                write_to_sysfs(remove_id_path, device_id_value)
            except Exception:
                # Ignore errors when removing
                pass

            # Try adding again
            write_to_sysfs(new_id_path, device_id_value)
        except Exception as e:
            logging.error(f"Failed to tag {device_type}: {e}")


def write_to_sysfs(path, value):
    """
    Write a value directly to a sysfs file.
    Assumes the script is run with appropriate permissions.

    Args:
        path (str): Path to the sysfs file
        value (str): Value to write

    Raises:
        IOError: If the write fails
    """
    with open(path, 'w') as f:
        f.write(value)


def main():
    parser = argparse.ArgumentParser(description='dstack VM Management Tool')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Setup command
    setup_parser = subparsers.add_parser('new', help='Setup a new instance')
    setup_parser.add_argument('compose_file', type=str,
                              help='Docker compose file')
    setup_parser.add_argument('-o', '--dir', type=str, help='Work directory')
    setup_parser.add_argument('-i', '--image', type=str, help='VM image path')
    setup_parser.add_argument(
        '-c', '--vcpus', type=int, default=1, help='Number of vCPUs')
    setup_parser.add_argument(
        '-m', '--memory', type=str, default='2G', help='Memory size (e.g., 1G, 512M)')
    setup_parser.add_argument('-d', '--disk', type=str,
                              default='20G', help='Disk size (e.g., 20G)')
    setup_parser.add_argument('-g', '--gpu', type=str,
                              action='append', help='GPU device')
    setup_parser.add_argument('-p', '--port', action='append', type=str,
                              help='Port mapping in format: protocol[:address]:from:to')
    setup_parser.add_argument('--local-key-provider', '--lkp',
                              action='store_true', help='Enable local key provider')
    setup_parser.add_argument(
        '--pin-numa', action='store_true', help='Pin vCPUs to NUMA node')
    setup_parser.add_argument(
        '--hugepages', action='store_true', help='Enable hugepages')

    # Start command
    start_parser = subparsers.add_parser('run', help='Start an instance')
    start_parser.add_argument('dir', type=str, help='Work directory')
    start_parser.add_argument('--imgdir', type=str, help='The image directory')
    start_parser.add_argument(
        '--kp-port', type=int, default=3443, help='The key provider listening port')
    start_parser.add_argument(
        '--dry-run', action='store_true', help='Run in dry run mode')

    # List Gpus command
    subparsers.add_parser('lsgpu', help='List available GPUs')

    # Tag VFIO command
    subparsers.add_parser(
        'tag-vfio', help='Tag NVIDIA GPUs and NVSwitches for VFIO passthrough')

    # Run the host server only
    serve_parser = subparsers.add_parser(
        'serve', help='Run the host server only')
    serve_parser.add_argument('dir', type=str, help='Work directory')
    serve_parser.add_argument(
        '--kp-port', type=int, default=3443, help='The key provider listening port')

    args = parser.parse_args()

    if args.command == 'new':
        manager = DstackManager()
        manager.setup_instance(args)
    elif args.command == 'run':
        manager = DstackManager()
        thread = start_server(args.dir, args.kp_port)
        manager.run_instance(args.dir, thread.host_port,
                             imgdir=args.imgdir, dry_run=args.dry_run)
    elif args.command == 'lsgpu':
        list_available_gpus()
    elif args.command == 'tag-vfio':
        tag_vfio()
    elif args.command == 'serve':
        thread = start_server(args.dir, args.kp_port)
        gen_vm_config(args.dir, thread.host_port)
        thread.join()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
