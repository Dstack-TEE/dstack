#!/usr/bin/env python3

import os
import sys
import json
import argparse
import requests
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import re

from typing import Optional, Dict, List


def encrypt_env(envs, hex_public_key: str) -> str:
    """
    Encrypts environment variables using a one-time X25519 key exchange and AES-GCM.
    
    This function does the following:
      1. Converts the given environment variables to JSON bytes.
      2. Removes a leading "0x" from the provided public key (if present) and converts it to bytes.
      3. Generates an ephemeral X25519 key pair.
      4. Computes a shared secret using this ephemeral private key and the remote public key.
      5. Uses the shared key directly as the 32-byte key for AES-GCM.
      6. Encrypts the JSON string with AES-GCM using a randomly generated IV.
      7. Concatenates the ephemeral public key, IV, and ciphertext and returns it as a hex string.
      
    Args:
        envs: The environment variables to encrypt. This can be any JSON-serializable data structure.
        hex_public_key: The remote encryption public key in hexadecimal format.
        
    Returns:
        A hexadecimal string that is the concatenation of:
          (ephemeral public key || IV || ciphertext).
    """
    # Serialize the environment variables to JSON and encode to bytes.
    envs_json = json.dumps({"env": envs}).encode("utf-8")

    # Remove the "0x" prefix if present.
    if hex_public_key.startswith("0x"):
        hex_public_key = hex_public_key[2:]
    
    # Convert the hexadecimal public key to bytes.
    remote_pubkey_bytes = bytes.fromhex(hex_public_key)
    
    # Generate an ephemeral X25519 key pair.
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_public_key = ephemeral_private_key.public_key()
    
    # Compute the shared secret using X25519.
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(remote_pubkey_bytes)
    shared = ephemeral_private_key.exchange(peer_public_key)
    
    # Use the shared secret as a key for AES-GCM encryption (AES-256 needs 32 bytes).
    aesgcm = AESGCM(shared)
    iv = os.urandom(12)  # 12-byte nonce (IV) for AES-GCM.
    ciphertext = aesgcm.encrypt(iv, envs_json, None)
    
    # Serialize the ephemeral public key to raw bytes.
    ephemeral_public_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    # Combine ephemeral public key, IV, and ciphertext.
    result = ephemeral_public_bytes + iv + ciphertext
    
    # Return the result as a hexadecimal string.
    return result.hex()


def parse_port_mapping(port_str: str) -> Dict:
    """Parse a port mapping string into a dictionary"""
    parts = port_str.split(':')
    if len(parts) == 3:
        return {
            "protocol": parts[0],
            "host_address": "127.0.0.1",
            "host_port": int(parts[1]),
            "vm_port": int(parts[2])
        }
    elif len(parts) == 4:
        return {
            "protocol": parts[0],
            "host_address": parts[1],
            "host_port": int(parts[2]),
            "vm_port": int(parts[3])
        }
    else:
        raise argparse.ArgumentTypeError(f"Invalid port mapping format: {port_str}")


class TeepodCLI:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.headers = {
            'Content-Type': 'application/json'
        }

    def rpc_call(self, method: str, params: Optional[Dict] = None) -> Dict:
        """Make an RPC call to the Teepod API"""
        url = f"{self.base_url}/prpc/Teepod.{method}?json"
        response = requests.post(url, headers=self.headers, json=params or {})
        if not response.ok:
            raise Exception(f"API call failed: {response.text}")
        return response.json()

    def list_vms(self, verbose: bool = False) -> None:
        """List all VMs and their status"""
        response = self.rpc_call('Status')
        vms = response['vms']

        if not vms:
            print("No VMs found")
            return

        headers = ['VM ID', 'App ID', 'Name', 'Status', 'Uptime']
        if verbose:
            headers.extend(['vCPU', 'Memory', 'Disk', 'Image'])

        rows = []
        for vm in vms:
            row = [
                vm['id'],
                vm['app_id'],
                vm['name'],
                vm['status'],
                vm.get('uptime', '-')
            ]

            if verbose:
                config = vm.get('configuration', {})
                row.extend([
                    config.get('vcpu', '-'),
                    f"{config.get('memory', '-')}MB",
                    f"{config.get('disk_size', '-')}GB",
                    config.get('image', '-')
                ])

            rows.append(row)

        print(format_table(rows, headers))

    def start_vm(self, vm_id: str) -> None:
        """Start a VM"""
        self.rpc_call('StartVm', {'id': vm_id})
        print(f"Started VM {vm_id}")

    def stop_vm(self, vm_id: str, force: bool = False) -> None:
        """Stop a VM"""
        if force:
            self.rpc_call('StopVm', {'id': vm_id})
            print(f"Forcefully stopped VM {vm_id}")
        else:
            self.rpc_call('ShutdownVm', {'id': vm_id})
            print(f"Gracefully shutting down VM {vm_id}")

    def remove_vm(self, vm_id: str) -> None:
        """Remove a VM"""
        self.rpc_call('RemoveVm', {'id': vm_id})
        print(f"Removed VM {vm_id}")

    def show_logs(self, vm_id: str, lines: int = 20, follow: bool = False) -> None:
        """Show VM logs"""
        url = f"{self.base_url}/logs?id={vm_id}&follow={str(follow).lower()}&ansi=false&lines={lines}"

        # Use stream=True for follow mode
        response = requests.get(url, headers=self.headers, stream=follow)
        if not response.ok:
            print(f"Failed to get logs: {response.text}")
            return

        if follow:
            try:
                # Stream the response line by line
                for line in response.iter_lines(decode_unicode=True):
                    if line:  # Filter out keep-alive empty lines
                        print(line)
            except KeyboardInterrupt:
                # Allow clean exit with Ctrl+C
                return
        else:
            print(response.text)

    def list_images(self) -> List[Dict]:
        """Get list of available images"""
        response = self.rpc_call('ListImages')
        return response['images']
    
    def get_app_env_encrypt_pub_key(self, app_id: str) -> Dict:
        """Get the encryption public key for the specified application ID"""
        response = self.rpc_call('GetAppEnvEncryptPubKey', {'app_id': app_id})
        return response['public_key']
    
    def calc_app_id(self, compose_file: str) -> str:
        """Calculate the application ID from the compose file"""
        compose_hash = hashlib.sha256(compose_file.encode()).hexdigest()
        return compose_hash[:40]

    def create_app_compose(self, name: str, prelaunch_script: str, docker_compose: str,
                           kms_enabled: bool, tproxy_enabled: bool,
                           public_logs: bool, public_sysinfo: bool,
                           output: str,
                           ) -> None:
        """Create a new app compose file"""
        app_compose = {
            "manifest_version": 2,
            "name": name,
            "runner": "docker-compose",
            "docker_compose_file": open(docker_compose, 'rb').read().decode('utf-8'),
            "kms_enabled": kms_enabled,
            "tproxy_enabled": tproxy_enabled,
            "public_logs": public_logs,
            "public_sysinfo": public_sysinfo,
        }
        if prelaunch_script:
            app_compose["prelaunch_script"] = prelaunch_script

        compose_file = json.dumps(app_compose, indent=4).encode('utf-8')
        compose_hash = hashlib.sha256(compose_file).hexdigest()
        with open(output, 'wb') as f:
            f.write(compose_file)
        print(f"App compose file created at: {output}")
        print(f"Compose hash: {compose_hash}")

    def create_vm(self, name: str, image: str, compose_file: str,
                 vcpu: int = 1, memory: int = 1024, disk_size: int = 20,
                 envs: Optional[Dict] = None,
                 app_id: Optional[str] = None,
                 ports: Optional[List[str]] = None,
                 ) -> None:
        """Create a new VM"""
        # Read and validate compose file
        if not os.path.exists(compose_file):
            raise Exception(f"Compose file not found: {compose_file}")

        with open(compose_file, 'r') as f:
            compose_content = f.read()

        # Create VM request
        params = {
            "name": name,
            "image": image,
            "compose_file": compose_content,
            "vcpu": vcpu,
            "memory": memory,
            "disk_size": disk_size,
            "app_id": app_id,
            "ports": [parse_port_mapping(port) for port in ports],
        }

        app_id = app_id or self.calc_app_id(compose_content)
        print(f"App ID: {app_id}")
        if envs:
            encrypt_pubkey = self.get_app_env_encrypt_pub_key(app_id)
            print(f"Encrypting environment variables with key: {encrypt_pubkey}")
            envs_list = [{"key": k, "value": v} for k, v in envs.items()]
            params["encrypted_env"] = encrypt_env(envs_list, encrypt_pubkey)
        response = self.rpc_call('CreateVm', params)
        print(f"Created VM with ID: {response.get('id')}")
        return response.get('id')

def format_table(rows, headers):
    """Simple table formatter"""
    if not rows:
        return ""

    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    # Create format string
    row_format = "│ " + " │ ".join(f"{{:<{w}}}" for w in widths) + " │"
    separator = "├─" + "─┼─".join("─" * w for w in widths) + "─┤"
    top_border = "┌─" + "─┬─".join("─" * w for w in widths) + "─┐"
    bottom_border = "└─" + "─┴─".join("─" * w for w in widths) + "─┘"

    # Build table
    table = [
        top_border,
        row_format.format(*headers),
        separator
    ]
    for row in rows:
        table.append(row_format.format(*[str(cell) for cell in row]))
    table.append(bottom_border)

    return "\n".join(table)

def parse_env_file(file_path: str) -> Dict[str, str]:
    """
    Parse an environment file where each line is formatted as:
      KEY=Value

    Lines that are empty or start with '#' are ignored.
    """
    if not file_path:
        return {}

    envs = {}
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            envs[key.strip()] = value.strip()
    return envs

def parse_size(s: str, target_unit: str) -> int:
    """
    Parse a human-readable size string (e.g. "1G", "100M") and return the size
    in the specified target unit.
    
    Args:
        s: The size string provided.
        target_unit: Either "MB" (for memory) or "GB" (for disk).
        
    Returns:
        An integer representing the size in the specified unit.
        
    Raises:
        argparse.ArgumentTypeError: if the format is invalid or if conversion turns
                                      out to be fractional.
    """
    s = s.strip()
    m = re.fullmatch(r'(\d+(?:\.\d+)?)([a-zA-Z]{1,2})?', s)
    if not m:
        raise argparse.ArgumentTypeError(f"Invalid size format: '{s}'")
    number_str, unit = m.groups()
    try:
        number = float(number_str)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid number in size: '{s}'")
    
    # If no unit is specified, assume the target unit.
    if unit is None:
        unit = target_unit
    else:
        unit = unit.upper()
    
    if target_unit == "MB":
        # For memory, if no suffix is provided we assume MB.
        if unit in ["M", "MB"]:
            factor = 1
        elif unit in ["G", "GB"]:
            factor = 1024
        elif unit in ["T", "TB"]:
            factor = 1024 * 1024
        else:
            raise argparse.ArgumentTypeError(f"Invalid size unit '{unit}' for memory. Use M, G, or T.")
    elif target_unit == "GB":
        # For disk, if no suffix is provided we assume GB.
        if unit in ["G", "GB"]:
            factor = 1
        elif unit in ["T", "TB"]:
            factor = 1024
        else:
            raise argparse.ArgumentTypeError(f"Invalid size unit '{unit}' for disk. Use G, T.")
    else:
        raise ValueError("Unsupported target unit")
    
    value = number * factor
    if not value.is_integer():
        raise argparse.ArgumentTypeError(f"Size must be an integer number of {target_unit}. Got {value}.")
    return int(value)

def parse_memory_size(s: str) -> int:
    """Parse a memory size string into MB."""
    return parse_size(s, "MB")

def parse_disk_size(s: str) -> int:
    """Parse a disk size string into GB."""
    return parse_size(s, "GB")

def main():
    parser = argparse.ArgumentParser(description='Teepod CLI - Manage VMs')
    parser.add_argument('--url', default='http://localhost:8080', help='Teepod API URL')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # List command
    list_parser = subparsers.add_parser('list', help='List VMs')
    list_parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed information')

    # Start command
    start_parser = subparsers.add_parser('start', help='Start a VM')
    start_parser.add_argument('vm_id', help='VM ID to start')

    # Stop command
    stop_parser = subparsers.add_parser('stop', help='Stop a VM')
    stop_parser.add_argument('vm_id', help='VM ID to stop')
    stop_parser.add_argument('-f', '--force', action='store_true', help='Force stop the VM')

    # Remove command
    remove_parser = subparsers.add_parser('remove', help='Remove a VM')
    remove_parser.add_argument('vm_id', help='VM ID to remove')

    # Logs command
    logs_parser = subparsers.add_parser('logs', help='Show VM logs')
    logs_parser.add_argument('vm_id', help='VM ID to show logs for')
    logs_parser.add_argument('-n', '--lines', type=int, default=20, help='Number of lines to show')
    logs_parser.add_argument('-f', '--follow', action='store_true', help='Follow log output')

    # Compose command
    compose_parser = subparsers.add_parser('compose', help='Create a new app-compose.json file')
    compose_parser.add_argument('--name', required=True, help='VM image name')
    compose_parser.add_argument('--docker-compose', required=True, help='Path to docker-compose.yml file')
    compose_parser.add_argument('--prelaunch-script', default=None, help='Path to prelaunch script')
    compose_parser.add_argument('--kms', action='store_true', help='Enable KMS')
    compose_parser.add_argument('--tproxy', action='store_true', help='Enable TProxy')
    compose_parser.add_argument('--public-logs', action='store_true', help='Enable public logs')
    compose_parser.add_argument('--public-sysinfo', action='store_true', help='Enable public sysinfo')
    compose_parser.add_argument('--output', required=True, help='Path to output app-compose.json file')

    # Deploy command
    deploy_parser = subparsers.add_parser('deploy', help='Deploy a new VM')
    deploy_parser.add_argument('--name', required=True, help='VM name')
    deploy_parser.add_argument('--image', required=True, help='VM image')
    deploy_parser.add_argument('--compose', required=True, help='Path to app-compose.json file')
    deploy_parser.add_argument('--vcpu', type=int, default=1, help='Number of vCPUs')
    deploy_parser.add_argument('--memory', type=parse_memory_size, default=1024, help='Memory size (e.g. 1G, 100M)')
    deploy_parser.add_argument('--disk', type=parse_disk_size, default=20, help='Disk size (e.g. 1G, 100M)')
    deploy_parser.add_argument('--env-file', help='File with environment variables to encrypt', default=None)
    deploy_parser.add_argument('--app-id', help='Application ID', default=None)
    deploy_parser.add_argument('--port', action='append', type=str, help='Port mapping in format: protocol[:address]:from:to')

    # Images command
    _images_parser = subparsers.add_parser('images', help='List available images')

    args = parser.parse_args()

    try:
        cli = TeepodCLI(args.url)

        if args.command == 'list':
            cli.list_vms(args.verbose)
        elif args.command == 'start':
            cli.start_vm(args.vm_id)
        elif args.command == 'stop':
            cli.stop_vm(args.vm_id, args.force)
        elif args.command == 'remove':
            cli.remove_vm(args.vm_id)
        elif args.command == 'logs':
            cli.show_logs(args.vm_id, args.lines, args.follow)
        elif args.command == 'compose':
            cli.create_app_compose(
                name=args.name,
                prelaunch_script=args.prelaunch_script,
                docker_compose=args.docker_compose,
                kms_enabled=args.kms,
                tproxy_enabled=args.tproxy,
                public_logs=args.public_logs,
                public_sysinfo=args.public_sysinfo,
                output=args.output
            )
        elif args.command == 'deploy':
            cli.create_vm(
                name=args.name,
                image=args.image,
                compose_file=args.compose,
                vcpu=args.vcpu,
                memory=args.memory,
                disk_size=args.disk,
                ports=args.port,
                envs=parse_env_file(args.env_file),
                app_id=args.app_id
            )
        elif args.command == 'images':
            images = cli.list_images()
            headers = ['Name', 'Version']
            rows = [[img['name'], img.get('version', '-')] for img in images]
            print(format_table(rows, headers))
        else:
            parser.print_help()

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()