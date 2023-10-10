# my\_rootkit

## Description
Projet de rootkit Linux pour l’École 2600.

## Dependancies
```bash
# Debian-like
sudo apt install build-essential git qemu-system-x86 libguestfs-tools flex libelf-dev docker.io
```

## Building
```bash
# Build modules and copy .ko files to ./modules/
make modules

# Cleanup files and delete ./modules/ directory
make clean
```

## Scripts
### General scripts
```bash
# Clone, configure, and build kernel, and create RootFS
./setup.sh

# Build modules and update RootFS
./build.sh
```

### Individual scripts
```bash
# Build kernel
# Clone and build latest stable release from Git branch 5.15.y
./scripts/make-git-kernel.sh

# Create RootFS and install kernel/modules/test files
# Also runs QEMU after installation
./scripts/make-rootfs.sh

# After modifications, update kernel/modules/test files
# Also runs QEMU after update
./scripts/update-kernel-img.sh

# Convert disk.img to disk.qcow2
./scripts/convert-qcow2.sh

# Update QCOW2 image with new kernel/modules/test files
# Also runs QEMU after update
./scripts/update-kernel-qcow2.sh

# Just run QEMU with disk.img file
./scripts/start-qemu.sh
```
