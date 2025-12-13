# Dstack on GCP with Intel TDX
# Supported zones: us-central1-a/b/c, us-east1-c/d, europe-west4-a/b/c, asia-southeast1-a/b/c

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }
}

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "zone" {
  type    = string
  default = "us-central1-a"
}

variable "machine_type" {
  type    = string
  default = "c3-standard-8"
}

variable "disk_size_gb" {
  type    = number
  default = 200
}

variable "ssh_public_key" {
  type    = string
  default = ""
}

variable "dstack_version" {
  type    = string
  default = "0.5.2"
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

resource "google_compute_network" "dstack" {
  provider                = google-beta
  name                    = "dstack-network"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "dstack" {
  provider      = google-beta
  name          = "dstack-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.dstack.id
}

resource "google_compute_firewall" "dstack" {
  provider = google-beta
  name     = "dstack-allow"
  network  = google_compute_network.dstack.name

  allow {
    protocol = "tcp"
    ports    = ["22", "9080", "9201", "9204", "9300"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["dstack"]
}

resource "google_compute_instance" "dstack_vmm" {
  provider     = google-beta
  name         = "dstack-vmm"
  machine_type = var.machine_type
  zone         = var.zone
  tags         = ["dstack"]

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = var.disk_size_gb
      type  = "pd-balanced"
    }
  }

  confidential_instance_config {
    confidential_instance_type  = "TDX"
    enable_confidential_compute = true
  }

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

    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential curl wget git docker.io jq

    systemctl enable docker && systemctl start docker
    usermod -aG docker ubuntu

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sudo -u ubuntu sh -s -- -y

    cd /home/ubuntu
    sudo -u ubuntu git clone https://github.com/Dstack-TEE/dstack.git
    mkdir -p vmm-data/{images,run}
    chown -R ubuntu:ubuntu vmm-data

    cd vmm-data
    wget -q "https://github.com/Dstack-TEE/meta-dstack/releases/download/v${var.dstack_version}/dstack-${var.dstack_version}.tar.gz" || true
    [ -f "dstack-${var.dstack_version}.tar.gz" ] && tar -xzf "dstack-${var.dstack_version}.tar.gz" -C images/ && rm "dstack-${var.dstack_version}.tar.gz"

    cd /home/ubuntu/dstack
    sudo -u ubuntu /home/ubuntu/.cargo/bin/cargo build --release -p dstack-vmm -p supervisor || true
    [ -f target/release/dstack-vmm ] && cp target/release/{dstack-vmm,supervisor} /home/ubuntu/vmm-data/

    cat > /home/ubuntu/vmm-data/vmm.toml << 'VMCFG'
address = "0.0.0.0:9080"
image_path = "./images"
run_path = "./run/vm"
[cvm]
kms_urls = ["http://127.0.0.1:9201"]
gateway_urls = ["http://127.0.0.1:9204"]
cid_start = 30000
cid_pool_size = 1000
[host_api]
port = 9300
[supervisor]
exe = "./supervisor"
sock = "./run/supervisor.sock"
VMCFG
    chown ubuntu:ubuntu /home/ubuntu/vmm-data/vmm.toml

    cat > /etc/systemd/system/dstack-vmm.service << 'SVC'
[Unit]
Description=Dstack VMM
After=network.target docker.service
[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/vmm-data
ExecStart=/home/ubuntu/vmm-data/dstack-vmm -c vmm.toml
Restart=always
[Install]
WantedBy=multi-user.target
SVC

    [ -f /home/ubuntu/vmm-data/dstack-vmm ] && systemctl daemon-reload && systemctl enable --now dstack-vmm
  EOF

  service_account {
    scopes = ["cloud-platform"]
  }

  allow_stopping_for_update = true
}

output "ip" {
  value = google_compute_instance.dstack_vmm.network_interface[0].access_config[0].nat_ip
}

output "ssh" {
  value = "ssh ubuntu@${google_compute_instance.dstack_vmm.network_interface[0].access_config[0].nat_ip}"
}

output "verify_tdx" {
  value = "ssh ubuntu@${google_compute_instance.dstack_vmm.network_interface[0].access_config[0].nat_ip} 'ls -la /dev/tdx_guest'"
}
