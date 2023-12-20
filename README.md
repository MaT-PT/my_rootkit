# my_rootkit

### Linux rootkit project for _École 2600_.

## Description

This is a LKM (Loadable Kernel Module) rootkit with stealth and persistence capabilities.

Based on Linux kernel LTS branch **5.15**.

It uses **syscall hooking** for most of its functionalities, and **signals** for userland communication.

This project also includes a complete **automated build system** (using Makefiles) for the kernel and the **root filesystem**, and easy **running with QEMU**.

### Features

#### RootFS

The whole process is automated using Makefiles.

The **kernel** is automatically downloaded from the official Linux Git repository, and the **root filesystem** is created from a minimal **Alpine Linux** image using Docker.

The RootFS is built with the following features:

-   Bootloader: **GRUB**
-   APK packages: `openrc`, `util-linux`, `build-base`, `vim`, `python3`, `strace`, `tmux`
    -   Allows for easy debugging and testing
-   Services:
    -   `devfs`: `/dev` filesystem
    -   `procfs`: `/proc` filesystem
    -   `sysfs`: `/sys` filesystem
    -   `networking`: internet access
    -   `local`: runs scripts at boot (used for rootkit persistence)
-   Users:
    -   `root`: password `root`
        -   RootFS automatically logs in as `root` after boot
    -   `user`: password `user` (or use `su -l user` to switch to this user)
        -   Has no special privileges, used to test privilege escalation
-   Shell: `ash` with colored prompt
-   Useful aliases:
    -   `user`: `su -l user` (switch to `user`)
    -   `ll`, `la`, `l`: classic `ls` aliases
        -   `ls` output is colored by default

#### Rootkit

-   **Stealth**: rootkit hides itself (_eg._ from `/proc/modules` and `/sys/module/`, used by `lsmod`)
    -   Can be reversed if necessary (_eg._ to unload the module)
    -   Also hides lines containing `"rootkit"` from `/proc/kmsg` and `/dev/kmsg` (for _eg._ `dmesg`), and syscall `sys_syslog`
    -   It also reverts the **kernel taint flag** by clearing the `TAINT_OOT_MODULE` bit
-   **Persistence**: rootkit copies itself to `/lib/modules/` and uses OpenRC's `local` service to get loaded at boot
-   **Elevate process privileges** to root
-   **Hide files and directories** by prefix (`rootkit_*` and `.rootkit_*`), recursively
-   **Hide processes** by PID (can also unhide them)
    -   Also hide processes whose executable name starts with the prefix
    -   **Child processes** are automatically hidden
-   **Hide TCP/UDP ports** by number, for **IPv4 and IPv6** (can also unhide them)
    -   Applies to both **local and foreign** ports, so it can be used for **bind and reverse shells**
-   **Authorize specific processes** (by PID) to **bypass** the rootkit's protections

The rookit **hooks a LOT of syscalls** whenever possible, so that hidden files can never be spotted (_eg._ can't be listed, opened, deleted, can't `cd` into a hidden directory, _etc._).

The full **list of hooked syscalls** is generated automatically from the kernel source code during the build process, and can be found in [`src/inc/hooked_syscalls.h`](src/inc/hooked_syscalls.h).

#### Signals

You can control the rootkit from userland using custom signals (defined in [`src/inc/uapi/rootkit.h`](src/inc/uapi/rootkit.h)):

-   `SIGROOT     = 42` -> **Elevate the current process** to root (needs `PID_SECRET`)
-   `SIGHIDE     = 43` -> **Hide a process** (add the PID to the hidden processes list)
-   `SIGSHOW     = 44` -> **Unhide a process** (remove the PID from the hidden processes list)
-   `SIGAUTH     = 45` -> **Authorize a process** (add the PID to the authorized processes list)
-   `SIGMODHIDE  = 46` -> **Hide the rootkit** (needs `PID_SECRET`)
-   `SIGMODSHOW  = 47` -> **Unhide the rootkit** (needs `PID_SECRET`)
-   `SIGPORTHIDE = 48` -> **Hide a port** (add the PID to the hidden ports list)
-   `SIGPORTSHOW = 49` -> **Unhide a port** (remove the PID from the hidden ports list)

The User API also defines the following constants:

-   `PID_SELF   = 0   ` -> PID of the **current process**
-   `PID_SECRET = 1337` -> **Secret PID** that has to be used when sending some signals

#### Example usage

```bash
# Become root (the current shell will be elevated)
kill -42 1337

# Hide current shell (PID 0 is the current process)
kill -43 0

# Hide process with PID 1234
kill -43 1234

# Unhide current shell
kill -44 0

# Unhide process with PID 1234
kill -44 1234

# Authorize current shell to bypass rootkit protections
kill -45 0

# Authorize process with PID 1234 to bypass rootkit protections
kill -45 1234

# Hide rootkit
kill -46 1337

# Unhide rootkit
kill -47 1337

# Hide port 12345
kill -48 12345

# Unhide port 12345
kill -49 12345
```

## Building

### Dependencies

```bash
# Debian-like
sudo apt install build-essential git qemu-system-x86 parted libguestfs-tools flex libelf-dev docker.io grub-pc-bin bison libssl-dev
```

### Build rootkit module

For all Makefile targets, any missing dependency will be automatically downloaded and/or built.

```bash
# Build rootkit.ko to ./build/
make

# Build rootkit.ko with debug printk enabled
make debug

# Build rootkit.ko with persistance disabled
make nopersist

# Copy build .ko files to ./modules/
make copy
```

### All-in-one Makefile targets

Use this command in a normal development process: it will clone the latest stable release from branch 5.15.y,
configure and build the kernel, create the RootFS, build the modules, update the RootFS, and run QEMU.
It also skips steps that are already up-to-date, so it can be used to quickly test the module after a modification.

```bash
# Build kernel and modules, create RootFS, update RootFS, and run QEMU
make run

# Build kernel and modules, create RootFS, update RootFS, and run QEMU with debug printk enabled
make debug run

# Update RootFS without starting QEMU
make update
```

### Customizable Makefile variables

You can override the following variables in the `make` command line:

```makefile
# Kernel branch
# Modules will be built against this branch
BRANCH = linux-5.15.y

# RootFS disk image file
DISK_IMG = disk.img

# Build directory
BUILD_DIR = $(call relpath,$(ROOT_DIR)/build)

# GCC options:

# Number of jobs to use for sub-make commands (Default: CPU cores + 1)
NJOBS = $(( `nproc` + 1 ))

# Load to use for sub-make commands (Default: 85% of CPU cores)
NLOAD = $(shell echo "$$(nproc) * 0.85" | bc)

# Temporary directory for build files
TMPDIR = /tmp
```

For example, to build the kernel from branch `linux-rolling-lts` with `8` jobs, and create the RootFS disk image file `rolling.img`, use the following command:

```bash
make BRANCH=linux-rolling-lts NJOBS=8 DISK_IMG=rolling.img run
```

To create a RootFS **QCOW2** disk image from file `rolling.img`, use the following command:

```bash
# This will create rolling.qcow2
make DISK_IMG=rolling.img qcow2
```

<details>
<summary><h3>Individual Makefile targets</h3></summary>

```bash
# Build rootkit module (default; implies make kernel_modules)
make modules

# Build rootkit module with debug printk enabled (implies make modules)
# (in debug mode, the module is not persistent)
make debug

# Build rootkit module with persistance disabled (implies make modules)
make nopersist

# Copy .ko files to ./modules/ (implies make modules)
make copy

# Cleanup rootkit build files
make clean

# Delete ./modules/ directory (implies make clean)
make mrproper

# Clone latest stable kernel release from branch 5.15.y
make clone

# Pull latest changes from branch 5.15.y (implies make clone)
make pull

# Configure kernel (implies make clone)
make config

# Build kernel bzImage (implies make config)
make kernel_bzimage

# Build kernel modules (implies make kernel)
make kernel_modules

# Build kernel and modules (implies make kernel_bzimage kernel_modules)
make kernel

# Generate kernel headers
make kernel_headers

# Create RootFS disk.img file
make rootfs

# Create RootFS disk.qcow2 file (implies make rootfs)
make qcow2

# Generate syscall hook header file (inc/hooked_syscalls.h)
make syscalls

# Strip symbols from build modules in ./modules/ (implies make copy)
# (experimental, usually breaks the module)
make strip

# Update RootFS with new kernel/modules/test files
# (implies make kernel_bzimage kernel_headers rootfs copy)
make update

# Run QEMU with disk.img image (implies make update)
make run

# Debug Makefile variables (does not build anything)
make vars
```

</details>
