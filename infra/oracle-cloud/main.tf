# Oracle Cloud Always Free — 2 Gotham relay nodes
#
# Provisions two Ampere ARM A1.Flex VMs (1 OCPU, 6 GB RAM each) in two
# distinct regions. Oracle's "Always Free" tier grants up to 4 OCPUs of
# Ampere A1 globally — using 2 here leaves headroom for a third node
# later if you want geographic diversity within Oracle alone.
#
# Requires:
#   - An Oracle Cloud account with payment method validated (Always Free
#     instances still require this — they just aren't billed).
#   - A tenancy OCID, user OCID, fingerprint, and private API key.
#     Generate via: https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm
#   - The OCI CLI authenticated (`oci setup config`), OR these values
#     populated in this file's `provider "oci"` block.
#
# Usage:
#   terraform -chdir=infra/oracle-cloud init
#   terraform -chdir=infra/oracle-cloud apply
#
# Output: the public IPv6 addresses of the two VMs. You will SSH into
# each and run `infra/scripts/install-relay.sh` to deploy the gotham-relay
# daemon.

terraform {
  required_version = ">= 1.5"
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "~> 5.0"
    }
  }
}

variable "compartment_ocid" {
  description = "OCID of the Oracle Cloud compartment to deploy into. Use your tenancy OCID for the root compartment."
  type        = string
}

variable "region_a" {
  description = "First region (e.g. eu-frankfurt-1, eu-paris-1, eu-amsterdam-1)."
  type        = string
  default     = "eu-frankfurt-1"
}

variable "region_b" {
  description = "Second region — pick a DIFFERENT geography for anonymity diversity."
  type        = string
  default     = "eu-amsterdam-1"
}

variable "ssh_pubkey_path" {
  description = "Path to your SSH public key. Will be installed on both VMs for the `ubuntu` user."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

provider "oci" {
  alias  = "a"
  region = var.region_a
  # tenancy_ocid, user_ocid, fingerprint, private_key_path
  # are picked up from ~/.oci/config by default.
}

provider "oci" {
  alias  = "b"
  region = var.region_b
}

# ─── VM #1 — region A ───────────────────────────────────────────────────

resource "oci_core_vcn" "a" {
  provider       = oci.a
  compartment_id = var.compartment_ocid
  cidr_blocks    = ["10.0.0.0/16"]
  display_name   = "gotham-relay-a-vcn"
}

resource "oci_core_internet_gateway" "a" {
  provider       = oci.a
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.a.id
  display_name   = "gotham-relay-a-igw"
}

resource "oci_core_route_table" "a" {
  provider       = oci.a
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.a.id
  display_name   = "gotham-relay-a-rt"
  route_rules {
    network_entity_id = oci_core_internet_gateway.a.id
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
  }
}

resource "oci_core_security_list" "a" {
  provider       = oci.a
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.a.id
  display_name   = "gotham-relay-a-sec"
  egress_security_rules {
    protocol    = "all"
    destination = "0.0.0.0/0"
  }
  # SSH for operator access.
  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options { min = 22, max = 22 }
  }
  # Gotham QUIC relay port (UDP 443 — same as HTTPS for DPI camouflage).
  ingress_security_rules {
    protocol = "17"
    source   = "0.0.0.0/0"
    udp_options { min = 443, max = 443 }
  }
}

resource "oci_core_subnet" "a" {
  provider          = oci.a
  compartment_id    = var.compartment_ocid
  vcn_id            = oci_core_vcn.a.id
  cidr_block        = "10.0.1.0/24"
  display_name      = "gotham-relay-a-subnet"
  route_table_id    = oci_core_route_table.a.id
  security_list_ids = [oci_core_security_list.a.id]
}

data "oci_core_images" "ubuntu_a" {
  provider                 = oci.a
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "22.04"
  shape                    = "VM.Standard.A1.Flex"
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

resource "oci_core_instance" "relay_a" {
  provider            = oci.a
  compartment_id      = var.compartment_ocid
  availability_domain = data.oci_identity_availability_domains.a.availability_domains[0].name
  shape               = "VM.Standard.A1.Flex"
  display_name        = "gotham-relay-a"

  shape_config {
    ocpus         = 1
    memory_in_gbs = 6
  }

  source_details {
    source_type = "image"
    source_id   = data.oci_core_images.ubuntu_a.images[0].id
  }

  create_vnic_details {
    subnet_id = oci_core_subnet.a.id
  }

  metadata = {
    ssh_authorized_keys = file(var.ssh_pubkey_path)
  }
}

data "oci_identity_availability_domains" "a" {
  provider       = oci.a
  compartment_id = var.compartment_ocid
}

# ─── VM #2 — region B (duplicated structure) ────────────────────────────

resource "oci_core_vcn" "b" {
  provider       = oci.b
  compartment_id = var.compartment_ocid
  cidr_blocks    = ["10.0.0.0/16"]
  display_name   = "gotham-relay-b-vcn"
}

resource "oci_core_internet_gateway" "b" {
  provider       = oci.b
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.b.id
  display_name   = "gotham-relay-b-igw"
}

resource "oci_core_route_table" "b" {
  provider       = oci.b
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.b.id
  display_name   = "gotham-relay-b-rt"
  route_rules {
    network_entity_id = oci_core_internet_gateway.b.id
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
  }
}

resource "oci_core_security_list" "b" {
  provider       = oci.b
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.b.id
  display_name   = "gotham-relay-b-sec"
  egress_security_rules {
    protocol    = "all"
    destination = "0.0.0.0/0"
  }
  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options { min = 22, max = 22 }
  }
  ingress_security_rules {
    protocol = "17"
    source   = "0.0.0.0/0"
    udp_options { min = 443, max = 443 }
  }
}

resource "oci_core_subnet" "b" {
  provider          = oci.b
  compartment_id    = var.compartment_ocid
  vcn_id            = oci_core_vcn.b.id
  cidr_block        = "10.0.1.0/24"
  display_name      = "gotham-relay-b-subnet"
  route_table_id    = oci_core_route_table.b.id
  security_list_ids = [oci_core_security_list.b.id]
}

data "oci_core_images" "ubuntu_b" {
  provider                 = oci.b
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "22.04"
  shape                    = "VM.Standard.A1.Flex"
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

resource "oci_core_instance" "relay_b" {
  provider            = oci.b
  compartment_id      = var.compartment_ocid
  availability_domain = data.oci_identity_availability_domains.b.availability_domains[0].name
  shape               = "VM.Standard.A1.Flex"
  display_name        = "gotham-relay-b"

  shape_config {
    ocpus         = 1
    memory_in_gbs = 6
  }

  source_details {
    source_type = "image"
    source_id   = data.oci_core_images.ubuntu_b.images[0].id
  }

  create_vnic_details {
    subnet_id = oci_core_subnet.b.id
  }

  metadata = {
    ssh_authorized_keys = file(var.ssh_pubkey_path)
  }
}

data "oci_identity_availability_domains" "b" {
  provider       = oci.b
  compartment_id = var.compartment_ocid
}

# ─── Outputs ────────────────────────────────────────────────────────────

output "relay_a_public_ip" {
  description = "Public IP of relay A. Use this in your gotham-bootstrap.json."
  value       = oci_core_instance.relay_a.public_ip
}

output "relay_a_ssh" {
  description = "Ready-to-paste SSH command for relay A."
  value       = "ssh ubuntu@${oci_core_instance.relay_a.public_ip}"
}

output "relay_b_public_ip" {
  description = "Public IP of relay B."
  value       = oci_core_instance.relay_b.public_ip
}

output "relay_b_ssh" {
  description = "Ready-to-paste SSH command for relay B."
  value       = "ssh ubuntu@${oci_core_instance.relay_b.public_ip}"
}
