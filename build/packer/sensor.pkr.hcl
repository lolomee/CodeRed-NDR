packer {
  required_plugins {
    qemu = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/qemu"
    }
    virtualbox = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/virtualbox"
    }
  }
}

variable "version" {
  type    = string
  default = "1.0.0"
}

variable "so_iso_url" {
  type        = string
  description = "URL or path to Security Onion ISO"
  default     = ""
}

variable "so_iso_checksum" {
  type    = string
  default = ""
}

variable "disk_size" {
  type    = string
  default = "81920"  # 80GB in MB
}

variable "memory" {
  type    = string
  default = "8192"
}

variable "cpus" {
  type    = string
  default = "4"
}

variable "output_directory" {
  type    = string
  default = "output"
}

# VirtualBox builder for OVA output
source "virtualbox-iso" "codered-sensor" {
  guest_os_type    = "Oracle_64"
  iso_url          = var.so_iso_url
  iso_checksum     = var.so_iso_checksum
  disk_size        = var.disk_size
  memory           = var.memory
  cpus             = var.cpus
  headless         = true
  format           = "ova"
  output_directory = "${var.output_directory}/codered-sensor-${var.version}"
  vm_name          = "codered-sensor-${var.version}"

  # Two NICs: management + monitoring
  vboxmanage = [
    ["modifyvm", "{{.Name}}", "--nic1", "nat"],
    ["modifyvm", "{{.Name}}", "--nic2", "intnet"],
    ["modifyvm", "{{.Name}}", "--intnet2", "monitor"],
    ["modifyvm", "{{.Name}}", "--nicpromisc2", "allow-all"],
    ["modifyvm", "{{.Name}}", "--audio", "none"],
    ["modifyvm", "{{.Name}}", "--usb", "off"],
  ]

  ssh_username     = "root"
  ssh_password     = "SecurityOnion"
  ssh_timeout      = "60m"
  shutdown_command  = "shutdown -P now"

  boot_wait = "10s"
  boot_command = [
    "<tab> inst.ks=http://{{ .HTTPIP }}:{{ .HTTPPort }}/ks.cfg<enter>"
  ]

  http_directory = "."
}

# QEMU builder for qcow2/raw output
source "qemu" "codered-sensor" {
  iso_url          = var.so_iso_url
  iso_checksum     = var.so_iso_checksum
  disk_size        = var.disk_size
  memory           = var.memory
  cpus             = var.cpus
  headless         = true
  format           = "qcow2"
  output_directory = "${var.output_directory}/codered-sensor-${var.version}"
  vm_name          = "codered-sensor-${var.version}"
  accelerator      = "kvm"

  ssh_username     = "root"
  ssh_password     = "SecurityOnion"
  ssh_timeout      = "60m"
  shutdown_command  = "shutdown -P now"

  boot_wait = "10s"
}

build {
  sources = ["source.virtualbox-iso.codered-sensor"]

  # Step 1: Base system packages
  provisioner "shell" {
    script = "scripts/01-base.sh"
  }

  # Step 2: Security Onion sensor setup
  provisioner "shell" {
    script = "scripts/02-so-install.sh"
    environment_vars = [
      "SO_ROLE=sensor",
    ]
    timeout = "45m"
  }

  # Step 3: Copy CodeRed overlay
  provisioner "file" {
    source      = "../../"
    destination = "/opt/codered/"
  }

  provisioner "shell" {
    script = "scripts/03-codered-overlay.sh"
    environment_vars = [
      "CODERED_VERSION=${var.version}",
    ]
  }

  # Step 4: Cleanup for distribution
  provisioner "shell" {
    script = "scripts/04-cleanup.sh"
  }

  post-processor "checksum" {
    checksum_types = ["sha256"]
    output         = "${var.output_directory}/codered-sensor-${var.version}.sha256"
  }
}
