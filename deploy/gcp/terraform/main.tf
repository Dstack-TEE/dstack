# Dstack on Google Cloud Platform with Intel TDX
#
# This Terraform configuration deploys Dstack components on GCP Confidential VMs
# using Intel TDX for hardware-based trusted execution.
#
# Supported zones for Intel TDX (c3-standard-*):
#   - us-central1-a, us-central1-b, us-central1-c
#   - us-east1-c, us-east1-d, us-east4-a, us-east4-c
#   - us-west1-a, us-west1-b
#   - europe-west4-a, europe-west4-b, europe-west4-c
#   - asia-southeast1-a, asia-southeast1-b, asia-southeast1-c
#
# Reference: https://cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }
}

# ============================================================
# Variables
# ============================================================
variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP Zone with Intel TDX support"
  type        = string
  default     = "us-central1-a"
}

variable "machine_type" {
  description = "Machine type (must support TDX: c3-standard-*)"
  type        = string
  default     = "c3-standard-8"
}

variable "disk_size_gb" {
  description = "Boot disk size in GB"
  type        = number
  default     = 200
}

variable "ssh_public_key" {
  description = "SSH public key for VM access"
  type        = string
  default     = ""
}

variable "dstack_version" {
  description = "Dstack version to deploy"
  type        = string
  default     = "0.5.2"
}

variable "network_name" {
  description = "VPC network name"
  type        = string
  default     = "dstack-network"
}

variable "enable_gpu" {
  description = "Enable GPU (requires a3-highgpu-1g and quota)"
  type        = bool
  default     = false
}

# ============================================================
# Providers
# ============================================================
provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

# ============================================================
# Network
# ============================================================
resource "google_compute_network" "dstack" {
  name                    = var.network_name
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "dstack" {
  name          = "${var.network_name}-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.dstack.id
}

resource "google_compute_firewall" "allow_ssh" {
  name    = "${var.network_name}-allow-ssh"
  network = google_compute_network.dstack.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["dstack"]
}

resource "google_compute_firewall" "allow_dstack" {
  name    = "${var.network_name}-allow-dstack"
  network = google_compute_network.dstack.name

  allow {
    protocol = "tcp"
    ports    = ["9080", "9201", "9204", "9300"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["dstack"]
}

# ============================================================
# Dstack VMM Host - Intel TDX Confidential VM
# ============================================================
resource "google_compute_instance" "dstack_vmm" {
  provider     = google-beta
  name         = "dstack-vmm"
  machine_type = var.machine_type
  zone         = var.zone

  tags = ["dstack", "vmm"]

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = var.disk_size_gb
      type  = "pd-balanced"  # Required for TDX
    }
  }

  # Enable Confidential Computing with Intel TDX
  confidential_instance_config {
    confidential_instance_type  = "TDX"
    enable_confidential_compute = true
  }

  # Required for TDX - no live migration
  scheduling {
    on_host_maintenance = "TERMINATE"
    automatic_restart   = true
  }

  network_interface {
    subnetwork = google_compute_subnetwork.dstack.id
    access_config {}
  }

  metadata = {
    ssh-keys = var.ssh_public_key != "" ? "ubuntu:${var.ssh_public_key}" : null
  }

  metadata_startup_script = <<-EOF
    #!/bin/bash
    set -e
    exec > >(tee /var/log/dstack-startup.log) 2>&1
    echo "Starting Dstack setup at $(date)"

    # Update system
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

    # Install dependencies
    apt-get install -y \
      build-essential \
      curl \
      wget \
      git \
      docker.io \
      jq

    # Enable Docker
    systemctl enable docker
    systemctl start docker
    usermod -aG docker ubuntu

    # Install Rust
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sudo -u ubuntu sh -s -- -y
    source /home/ubuntu/.cargo/env

    # Clone Dstack
    cd /home/ubuntu
    sudo -u ubuntu git clone https://github.com/Dstack-TEE/dstack.git

    # Create data directory
    mkdir -p /home/ubuntu/vmm-data/{images,run}
    chown -R ubuntu:ubuntu /home/ubuntu/vmm-data

    # Download guest image
    DSTACK_VERSION="${var.dstack_version}"
    cd /home/ubuntu/vmm-data
    wget -q "https://github.com/Dstack-TEE/meta-dstack/releases/download/v$${DSTACK_VERSION}/dstack-$${DSTACK_VERSION}.tar.gz" || true
    if [ -f "dstack-$${DSTACK_VERSION}.tar.gz" ]; then
      tar -xzf "dstack-$${DSTACK_VERSION}.tar.gz" -C images/
      rm "dstack-$${DSTACK_VERSION}.tar.gz"
    fi

    # Build VMM
    cd /home/ubuntu/dstack
    sudo -u ubuntu /home/ubuntu/.cargo/bin/cargo build --release -p dstack-vmm -p supervisor || true

    # Copy binaries
    if [ -f target/release/dstack-vmm ]; then
      cp target/release/dstack-vmm /home/ubuntu/vmm-data/
      cp target/release/supervisor /home/ubuntu/vmm-data/
      chown ubuntu:ubuntu /home/ubuntu/vmm-data/dstack-vmm
      chown ubuntu:ubuntu /home/ubuntu/vmm-data/supervisor
    fi

    # Create VMM config
    cat > /home/ubuntu/vmm-data/vmm.toml << 'VMCFG'
    address = "0.0.0.0:9080"
    reuse = true
    image_path = "./images"
    run_path = "./run/vm"

    [cvm]
    kms_urls = ["http://127.0.0.1:9201"]
    gateway_urls = ["http://127.0.0.1:9204"]
    cid_start = 30000
    cid_pool_size = 1000

    [cvm.port_mapping]
    enabled = true
    address = "0.0.0.0"
    range = [
        { protocol = "tcp", from = 1, to = 20000 },
        { protocol = "udp", from = 1, to = 20000 },
    ]

    [host_api]
    port = 9300

    [supervisor]
    exe = "./supervisor"
    sock = "./run/supervisor.sock"
    pid_file = "./run/supervisor.pid"
    log_file = "./run/supervisor.log"
    detached = false
    auto_start = true
    VMCFG
    chown ubuntu:ubuntu /home/ubuntu/vmm-data/vmm.toml

    # Create systemd service
    cat > /etc/systemd/system/dstack-vmm.service << 'SVCEOF'
    [Unit]
    Description=Dstack VMM Service
    After=network.target docker.service

    [Service]
    Type=simple
    User=ubuntu
    WorkingDirectory=/home/ubuntu/vmm-data
    ExecStart=/home/ubuntu/vmm-data/dstack-vmm -c vmm.toml
    Restart=always
    RestartSec=10

    [Install]
    WantedBy=multi-user.target
    SVCEOF

    # Start if binary exists
    if [ -f /home/ubuntu/vmm-data/dstack-vmm ]; then
      systemctl daemon-reload
      systemctl enable dstack-vmm
      systemctl start dstack-vmm
    fi

    echo "Dstack setup complete at $(date)"
  EOF

  service_account {
    scopes = ["cloud-platform"]
  }

  allow_stopping_for_update = true
}

# ============================================================
# Outputs
# ============================================================
output "vmm_external_ip" {
  description = "External IP of Dstack VMM"
  value       = google_compute_instance.dstack_vmm.network_interface[0].access_config[0].nat_ip
}

output "vmm_internal_ip" {
  description = "Internal IP of Dstack VMM"
  value       = google_compute_instance.dstack_vmm.network_interface[0].network_ip
}

output "ssh_command" {
  description = "SSH command to connect to VMM"
  value       = "ssh ubuntu@${google_compute_instance.dstack_vmm.network_interface[0].access_config[0].nat_ip}"
}

output "vmm_endpoint" {
  description = "VMM Web UI URL"
  value       = "http://${google_compute_instance.dstack_vmm.network_interface[0].access_config[0].nat_ip}:9080"
}

output "tdx_verification" {
  description = "Command to verify TDX is working"
  value       = "ssh ubuntu@${google_compute_instance.dstack_vmm.network_interface[0].access_config[0].nat_ip} 'ls -la /dev/tdx_guest'"
}

