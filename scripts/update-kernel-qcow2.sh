#!/bin/bash

########################################################################
if [ -z "$DISK_IMG" ]; then
    DISK_IMG="disk.qcow2"
    IMG_FORMAT="qcow2"
fi
if [ -z "$ROOTFS" ]; then
    ROOTFS="/tmp/my-rootfs"
fi
if [ -z "$KERNEL_DIR" ]; then
    KERNEL_DIR="$(find -maxdepth 1 -type d -name 'linux-*' | sort -V | tail -n 1)"
fi
KERNEL="${KERNEL_DIR}/arch/x86/boot/bzImage"
PARTITION="/dev/sda1"
TEST_DIR="$(dirname -- "$0")/tests"
if [ -z "$MODULE_DIR" ]; then
    MODULE_DIR="./modules"
fi
if [ -z "$COMPANION" ]; then
    COMPANION="./companion/companion"
fi
########################################################################

if [ -z "$KERNEL_DIR" ]; then
    echo "* Error: Could not find kernel source directory, try running $(dirname -- "$0")/make-git-kernel.sh"
    return 1 2> /dev/null || exit 1
fi

if [ ! -f "$KERNEL" ]; then
    echo "* Error: Kernel file $KERNEL not found, try running $(dirname -- "$0")/make-git-kernel.sh"
    return 1 2> /dev/null || exit 1
fi

echo "* Using kernel: $KERNEL"
echo

if [ ! -f "$DISK_IMG" ]; then
    echo "* Error: Disk image file $DISK_IMG not found"
    return 1 2> /dev/null || exit 1
fi

# Mount partition
echo -n "* Mounting partition $PARTITION from $DISK_IMG on $ROOTFS..."
mkdir -p -- "$ROOTFS"
sudo guestmount --add "$DISK_IMG" --mount "$PARTITION" "$ROOTFS"
echo " done"

# Update kernel and test files
echo "* Updating kernel and test files..."
echo -n "  * "
sudo cp -v -- "$KERNEL" "${ROOTFS}/boot/vmlinuz"

if [ -d "$TEST_DIR" ]; then
    sudo cp -rv -- "${TEST_DIR}/." "${ROOTFS}/root/" | grep -Fv '.vscode' | sed 's/^/  * /'
    sudo rm -rf -- "${ROOTFS}/root/.vscode"
else
    echo "  * Warning: test dir $TEST_DIR not found, skipping..."
fi
echo "* Done"

# Update companion program
echo "* Updating companion program..."
echo -n "  * "
sudo cp -v -- "$COMPANION" "${ROOTFS}/home/user/"
sudo chown -- user:user "${ROOTFS}/home/user/companion"
echo "* Done"

# Install kernel modules
echo "* Installing kernel modules..."
sudo make -C "$KERNEL_DIR" modules_install INSTALL_MOD_PATH="$ROOTFS"
echo "* Done"

# Install Linux headers
echo "* Installing Linux headers..."
sudo make -C "$KERNEL_DIR" headers_install INSTALL_HDR_PATH="$ROOTFS/usr"
echo "* Done"

# Update modules
echo "* Updating modules..."
sudo find "$MODULE_DIR" -type f -name '*.ko' -exec echo -n '   * ' \; \
    -exec cp -v -- '{}' "${ROOTFS}/root/" \;
echo "* Done"

# Cleanup
echo -n "* Unmounting $ROOTFS..."
sync
sudo guestunmount --retry=1 -- "$ROOTFS"
rmdir -- "$ROOTFS"
echo " done"

if [ "$1" != "--no-qemu" ]; then
    # Run QEMU
    echo
    export DISK_IMG IMG_FORMAT
    $(dirname -- "$0")/start-qemu.sh
fi

ret=$?
return $ret 2> /dev/null || exit $ret
