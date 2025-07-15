#!/usr/bin/env python3
"""
dstack-backup.py - Periodic backup script for dstack VMM
This script ensures each running VM gets:
- Full backup once a week
- Incremental backup once a day

Prerequisites:
- Install https://github.com/kvinwang/qmpbackup
- Enable qmp socket in dstack-vmm config

Usage:
  ./dstack-backup.py [options]

Arguments:
  --vmm-work-dir DIR      dstack-vmm work directory [default: .]
  --vms-dir DIR           Directory containing VM run data [default: <vmm-work-dir>/run/vm]
  --backup-dir DIR        Directory for storing backups [default: <vmm-work-dir>/run/backup]
  --log-file FILE         File for storing logs [default: <vmm-work-dir>/logs/backup.log]
  --state-file FILE       File for storing backup state [default: <vmm-work-dir>/state/backup_state.json]
  --full-interval PERIOD  Interval for full backups (e.g., 7d for 7 days) [default: 7d]
  --inc-interval PERIOD   Interval for incremental backups (e.g., 1d for 1 day) [default: 1d]
  --log-level LEVEL       Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) [default: INFO]
"""

import sys
import os
import time
import json
import logging
import argparse
import subprocess
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from logging.handlers import RotatingFileHandler

# Set up logger
logger = logging.getLogger(__name__)


def parse_version(image_name: str) -> Tuple[int, int, int]:
    """Parse the version from the image name"""
    version = image_name.split("-")[-1]
    return tuple(map(int, version.split(".")))


class BackupScheduler:
    """Scheduler for VM backups"""

    def __init__(self, vms_dir, backup_dir, state_file, full_interval_seconds, inc_interval_seconds, max_backups=4, vm_filter=None):
        self.vms_dir = vms_dir
        self.backup_dir = backup_dir
        self.state_file = state_file
        self.full_interval_seconds = full_interval_seconds
        self.inc_interval_seconds = inc_interval_seconds
        self.max_backups = max_backups
        self.vm_filter = vm_filter
        self.state = self._load_state()

    def _load_state(self) -> Dict:
        """Load backup state from JSON file"""
        if not self.state_file.exists():
            return {}

        try:
            with open(self.state_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            logger.warning(
                "Failed to load state file, starting with empty state")
            return {}

    def _save_state(self):
        """Save backup state to JSON file"""
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=2)

    def get_running_vms(self, vm_filter: Optional[str] = None) -> List[Dict[str, str]]:
        """Returns a list of running VMs with their IDs and names"""
        logger.info("Getting list of running VMs...")
        vms = []

        if not self.vms_dir.exists():
            logger.warning(f"VMs directory {self.vms_dir} does not exist")
            return vms

        # Iterate through VM directories
        for vm_dir in self.vms_dir.iterdir():
            if not vm_dir.is_dir():
                logger.debug(f"Skipping non-directory {vm_dir}")
                continue

            vm_id = vm_dir.name
            if vm_filter and vm_filter.strip() not in vm_id:
                continue
            pid_file = vm_dir / "qemu.pid"

            if not pid_file.exists():
                logger.debug(f"No PID file found for VM {vm_id}")
                continue

            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, 0)
            except (ValueError, ProcessLookupError):
                logger.debug(f"No running process found for VM {vm_id}")
                continue
            except OSError as e:
                logger.debug(f"Failed to check process for VM {vm_id}: {e}")
                if e.errno == 1:  # Operation not permitted
                    pass
                else:
                    continue

            manifest_file = vm_dir / "vm-manifest.json"
            if not manifest_file.exists():
                logger.debug(f"No manifest file found for VM {vm_id}")
                continue

            qmp_socket = vm_dir / "qmp.sock"
            if not qmp_socket.exists():
                logger.debug(f"No QMP socket found for VM {vm_id}")
                continue

            try:
                with open(manifest_file, 'r') as f:
                    manifest = json.load(f)
                    image = manifest.get('image') or ""
                    if not image.startswith("dstack-"):
                        logger.debug(
                            f"Image {image} is not a dstack image, skipping")
                        continue
                    version_tuple = parse_version(image)
                    if version_tuple < (0, 5, 0):
                        hd = "hd0"
                    else:
                        hd = "hd1"
                    vm_name = manifest.get(
                        'name') or manifest.get('id') or vm_id

                    vms.append({
                        'id': vm_id,
                        'name': vm_name,
                        'hd': hd
                    })
                    logger.debug(f"Found running VM: {vm_name} ({vm_id})")
            except (json.JSONDecodeError, IOError) as e:
                logger.error(f"Failed to read manifest for VM {vm_id}: {e}")

        logger.info(f"Found {len(vms)} running VMs")

        return vms

    def get_last_backup_time(self, vm_id: str, backup_type: str) -> Optional[int]:
        """Get the timestamp of the last backup of specified type for a VM"""
        logger.debug(
            f"Looking for {backup_type} backup timestamp for VM {vm_id}")

        if vm_id not in self.state:
            logger.debug(f"VM {vm_id} not found in state file")
            return None

        timestamp = self.state[vm_id].get(backup_type)
        if timestamp:
            logger.debug(
                f"Retrieved {backup_type} backup timestamp for VM {vm_id}: {timestamp}")

        return timestamp

    def update_backup_time(self, vm_id: str, backup_type: str):
        """Update the timestamp for a backup type"""
        current_time = int(time.time())

        if vm_id not in self.state:
            self.state[vm_id] = {}

        self.state[vm_id][backup_type] = current_time
        self._save_state()

        logger.debug(
            f"Updated {backup_type} backup timestamp for VM {vm_id} to {datetime.fromtimestamp(current_time)}")

    def perform_backup(self, vm_id: str, vm_name: str, backup_type: str, hd: str) -> bool:
        """Perform a backup for the specified VM"""
        logger.info(f"Performing {backup_type} backup...")

        # Convert to absolute paths
        vm_dir = self.vms_dir.resolve() / vm_id
        backup_dir = self.backup_dir.resolve() / vm_id / "backups"
        qmp_socket = vm_dir / "qmp.sock"

        # Create backup directory if it doesn't exist
        backup_dir.mkdir(parents=True, exist_ok=True)

        # Set backup level based on type
        backup_level = "full" if backup_type == "full" else "inc"

        # Create or update latest symlink
        latest_dir = backup_dir / "latest"

        if backup_level == "full":
            # Create timestamped directory for this backup
            timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
            backup_timestamp_dir = backup_dir / f"{timestamp}"
            backup_timestamp_dir.mkdir(parents=True, exist_ok=True)
            try:
                latest_dir.unlink()
            except FileNotFoundError:
                pass
            latest_dir.symlink_to(timestamp)

        # For full backups, clear bitmaps first
        if backup_level == "full":
            logger.info(f"Clearing bitmaps for full backup of VM {vm_name}")
            if qmp_socket.exists():
                try:
                    # Use absolute path for qmp_socket
                    abs_qmp_socket = qmp_socket.resolve()
                    result = subprocess.run(
                        ["qmpbackup", "--socket",
                            str(abs_qmp_socket), "cleanup", "--remove-bitmap"],
                        capture_output=True,
                        text=True
                    )
                    if result.returncode != 0:
                        logger.warning(
                            f"Failed to clear bitmaps for VM {vm_name} ({vm_id}): {result.stderr}")
                        # Continue anyway as this might be the first backup
                except Exception as e:
                    logger.error(f"Error clearing bitmaps: {e}")
            else:
                logger.error(f"QMP socket not found at {qmp_socket}")
                return False

        # Perform the backup
        logger.debug(f"Running qmpbackup")

        # Convert to absolute paths for qmpbackup
        abs_qmp_socket = qmp_socket.resolve()
        abs_latest_dir = latest_dir.resolve()

        logger.debug(
            f"Running: qmpbackup --socket {abs_qmp_socket} backup -i {hd} --no-subdir -t {abs_latest_dir} -l {backup_level}")
        if qmp_socket.exists():
            try:
                result = subprocess.run(
                    [
                        "qmpbackup",
                        "--socket", str(abs_qmp_socket),
                        "backup",
                        "-i", hd,
                        "--no-subdir",
                        "-t", str(abs_latest_dir),
                        "-l", backup_level
                    ],
                    capture_output=True,
                    text=True
                )

                if result.returncode == 0:
                    logger.debug(f"Backup successful")
                    self.update_backup_time(vm_id, backup_type)

                    # Rotate backups if needed
                    if backup_type == "full":
                        self._rotate_backups(vm_id)
                    return True
                else:
                    logger.error(
                        f"Backup failed: {result.stderr} : {result.stdout}")
                    return False
            except Exception as e:
                logger.error(f"Error performing backup: {e}")
                return False
        else:
            logger.error(f"QMP socket not found at {qmp_socket}")
            return False

    def needs_backup(self, vm_id: str) -> Optional[str]:
        """Determine if a VM needs a backup and what type"""
        current_time = int(time.time())
        last_full = self.get_last_backup_time(vm_id, "full")
        last_full_ts = datetime.fromtimestamp(last_full) if last_full else None
        last_incremental = self.get_last_backup_time(vm_id, "incremental")
        last_incremental_ts = datetime.fromtimestamp(
            last_incremental) if last_incremental else None

        logger.debug(f"Last full backup: {last_full_ts}")
        logger.debug(f"Last incremental backup: {last_incremental_ts}")

        # Determine if we need a full backup based on configured interval
        if not last_full or (current_time - last_full) > self.full_interval_seconds:
            return "full"
        # Determine if we need an incremental backup based on configured interval
        elif not last_incremental or (current_time - last_incremental) > self.inc_interval_seconds:
            return "incremental"
        else:
            return None

    def _rotate_backups(self, vm_id):
        """Remove old backups to keep only max_backups"""
        backup_dir = self.backup_dir.resolve() / vm_id / "backups"
        if not backup_dir.exists():
            return

        # Get all backup directories (excluding 'latest' symlink)
        backup_dirs = [d for d in backup_dir.iterdir()
                       if d.is_dir() and d.name != "latest"]

        # Sort by name (which is timestamp format)
        backup_dirs.sort()

        # If we have more backups than max_backups, remove the oldest ones
        if len(backup_dirs) > self.max_backups:
            logger.info(
                f"Rotating backups for VM {vm_id}, keeping {self.max_backups} most recent")
            for old_dir in backup_dirs[:-self.max_backups]:
                logger.info(
                    f"Removing old backup: {os.path.basename(old_dir)}")
                try:
                    shutil.rmtree(old_dir)
                except Exception as e:
                    logger.error(f"Failed to remove old backup {old_dir}: {e}")

    def run(self):
        """Main entry point for the backup scheduler"""
        logger.info("=" * 80)
        logger.info(f"Starting backup scheduler")
        logger.info(f"Using VMs directory: {self.vms_dir}")
        logger.info(f"Using backup directory: {self.backup_dir}")

        # Get list of running VMs
        vms = self.get_running_vms(self.vm_filter)

        if not vms:
            logger.info("No running VMs found")
            return

        # Process each VM
        for vm in vms:
            vm_id = vm['id']
            vm_name = vm['name']
            hd = vm['hd']

            logger.info("-" * 50)
            logger.info(f"Processing VM: {vm_name} ({vm_id})")

            # Check if backup is needed
            backup_type = self.needs_backup(vm_id)

            if not backup_type:
                logger.info(f"No backup needed")
                continue

            # Perform backup
            start_time = time.time()
            if self.perform_backup(vm_id, vm_name, backup_type, hd):
                elapsed_time = time.time() - start_time
                logger.info(
                    f"{backup_type} backup completed successfully (total time: {elapsed_time:.2f}s)")
            else:
                elapsed_time = time.time() - start_time
                logger.error(
                    f"{backup_type} backup failed (time elapsed: {elapsed_time:.2f}s)")

        logger.info("-" * 50)
        logger.info("Backup scheduler run completed")


def parse_interval(interval_str):
    """Parse interval string like '7d' or '12h' into seconds"""
    if not interval_str:
        raise ValueError("Interval cannot be empty")

    # Get the unit (last character) and value (everything else)
    unit = interval_str[-1].lower()
    try:
        value = int(interval_str[:-1])
    except ValueError:
        raise ValueError(
            f"Invalid interval format: {interval_str}. Expected format like '7d' or '12h'")

    # Convert to seconds based on unit
    if unit == 'd':
        return value * 24 * 60 * 60  # days to seconds
    elif unit == 'h':
        return value * 60 * 60  # hours to seconds
    elif unit == 'm':
        return value * 60  # minutes to seconds
    elif unit == 's':
        return value  # already in seconds
    else:
        raise ValueError(
            f"Unknown time unit: {unit}. Use d (days), h (hours), m (minutes), or s (seconds)")


def parse_args():
    """Parse command line arguments"""
    # First parse just the vmm-work-dir to use it for defaults
    temp_parser = argparse.ArgumentParser(add_help=False)
    temp_parser.add_argument("--vmm-work-dir", type=Path, default=".")
    temp_args, _ = temp_parser.parse_known_args()
    vmm_work_dir = temp_args.vmm_work_dir

    # Now create the real parser with all arguments
    parser = argparse.ArgumentParser(
        description="Periodic backup script for dstack VMM")

    # Add all arguments with proper defaults
    parser.add_argument("--vmm-work-dir", type=Path,
                        default=".",
                        help="dstack-vmm work directory")
    parser.add_argument("--vms-dir", type=Path,
                        default=vmm_work_dir / "run" / "vm",
                        help="Directory containing VM run data")
    parser.add_argument("--backup-dir", type=Path,
                        default=vmm_work_dir / "run" / "backup",
                        help="Directory for storing backups")
    parser.add_argument("--log-file", type=Path,
                        default=vmm_work_dir / "logs" / "backup.log",
                        help="Log file path (with rotation enabled)")
    parser.add_argument("--state-file", type=Path,
                        default=vmm_work_dir / "state" / "backup_state.json",
                        help="File for storing backup state")
    parser.add_argument("--full-interval", type=str,
                        default="7d",
                        help="Interval for full backups (e.g., 7d for 7 days)")
    parser.add_argument("--inc-interval", type=str,
                        default="1d",
                        help="Interval for incremental backups (e.g., 1d for 1 day)")
    parser.add_argument("--max-backups", type=int, default=4,
                        help="Maximum number of full backups to keep per VM")
    parser.add_argument("--log-level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)")
    parser.add_argument("--vm-filter", type=str, help="Filter VMs by ID")

    # Parse all arguments
    args = parser.parse_args()

    # Parse interval strings into seconds
    args.full_interval_seconds = parse_interval(args.full_interval)
    args.inc_interval_seconds = parse_interval(args.inc_interval)

    return args


def setup_logging(log_file: Path, log_level: str = "INFO"):
    """Set up logging configuration"""
    # Create logs directory if it doesn't exist
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Map string log level to logging constants
    log_level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }

    # Get the numeric log level (default to INFO if invalid)
    numeric_level = log_level_map.get(log_level.upper(), logging.INFO)

    # Create a rotating file handler (10MB size limit, 3 backup files)
    file_handler = RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=3)
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"))

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"))

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add our handlers
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)


def main():
    """Main entry point"""
    try:
        # Parse command line arguments
        args = parse_args()

        # Set up logging with specified log file and log level
        setup_logging(args.log_file, args.log_level)

        # Create directories if they don't exist
        args.backup_dir.mkdir(parents=True, exist_ok=True)
        args.state_file.parent.mkdir(parents=True, exist_ok=True)

        # Initialize and run scheduler
        scheduler = BackupScheduler(
            args.vms_dir, args.backup_dir, args.state_file,
            args.full_interval_seconds, args.inc_interval_seconds,
            args.max_backups, args.vm_filter)
        scheduler.run()
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
