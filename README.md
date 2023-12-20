# my\_rootkit

## Description

Linux rootkit project for *École 2600*.

## Dependencies

```bash
# Debian-like
sudo apt install build-essential git qemu-system-x86 parted libguestfs-tools flex libelf-dev docker.io grub-pc-bin bison libssl-dev
```

## Building

### All-in-one Makefile target

Use this command in a normal build process: it will clone the latest stable release from branch 5.15.y, configure and build the kernel, create the RootFS, build the modules, update the RootFS, and run QEMU.
It also skips steps that are already up-to-date, so it can be used to quickly test the module after a modification.

```bash
make run
```

### Customizable Makefile variables

You can override the following variables in the `make` command line:

```makefile
# Kernel branch
BRANCH = linux-5.15.y

# RootFS disk image file
DISK_IMG = disk.img

# Number of jobs to use for sub-make commands
NJOBS = $(( `nproc` + 1 ))
```

For example, to build the kernel from branch `linux-rolling-lts` with `8` jobs, and create the RootFS disk image file `rolling.img`, use the following command:

```bash
make BRANCH=linux-rolling-lts NJOBS=8 DISK_IMG=rolling.img run
```

### Individual Makefile targets

```bash
# Build modules (default, implies make kernel_modules)
make modules

# Copy .ko files to ./modules/ (implies make modules)
make copy

# Cleanup files
make clean

# Delete ./modules/ directory (implies make clean)
make mrproper

# Clone latest stable release from branch 5.15.y
make clone

# Pull latest changes from branch 5.15.y (implies make clone)
make pull

# Configure kernel (implies make clone)
make config

# Build kernel (implies make config)
make kernel

# Build kernel modules (implies make kernel)
make kernel_modules

# Create RootFS disk.img file
make rootfs

# Create RootFS disk.qcow2 file (implies make rootfs)
make qcow2

# Update RootFS with new kernel/modules/test files
# (implies make kernel rootfs copy)
make update

# Run QEMU with disk.img image (implies make update)
make run
```

## Scripts

**WARNING**: prefer using Makefile targets instead of scripts, as they are more flexible.

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
