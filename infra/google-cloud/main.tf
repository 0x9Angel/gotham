
terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

variable "project_id" {
  description = "Google Cloud project ID."
  type        = string
}

variable "region" {
  description = "Free-tier eligible region — us-west1, us-central1, or us-east1."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Zone within the region."
  type        = string
  default     = "us-central1-a"
}

variable "ssh_user" {
  description = "OS user that gets the SSH key. Convention: same as your local username."
  type        = string
  default     = "angel"
}

variable "ssh_pubkey_path" {
  description = "Path to your SSH public key."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

resource "google_compute_network" "gotham" {
  name                    = "gotham-relay-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "gotham" {
  name          = "gotham-relay-subnet"
  network       = google_compute_network.gotham.id
  ip_cidr_range = "10.10.0.0/24"
  region        = var.region
}

resource "google_compute_firewall" "ssh" {
  name    = "gotham-allow-ssh"
  network = google_compute_network.gotham.id
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
  direction     = "INGRESS"
}

resource "google_compute_firewall" "gotham_quic" {
  name    = "gotham-allow-quic"
  network = google_compute_network.gotham.id
  allow {
    protocol = "udp"
    ports    = ["443"]
  }
  source_ranges = ["0.0.0.0/0"]
  direction     = "INGRESS"
}

resource "google_compute_instance" "relay" {
  name         = "gotham-relay-c"
  machine_type = "e2-micro"
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = 10
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.gotham.id
    access_config {
    }
  }

  metadata = {
    ssh-keys = "${var.ssh_user}:${file(var.ssh_pubkey_path)}"
  }

  tags = ["gotham-relay"]
}

output "relay_c_public_ip" {
  description = "Public IP of relay C. Use this in your gotham-bootstrap.json."
  value       = google_compute_instance.relay.network_interface[0].access_config[0].nat_ip
}

output "relay_c_ssh" {
  description = "Ready-to-paste SSH command for relay C."
  value       = "ssh ${var.ssh_user}@${google_compute_instance.relay.network_interface[0].access_config[0].nat_ip}"
}
