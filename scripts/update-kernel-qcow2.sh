#!/bin/bash

########################################################################
DISK_IMG="disk.qcow2"
IMG_FORMAT="qcow2"
ROOTFS="/tmp/my-rootfs"
PARTITION="/dev/sda1"
KERNEL_DIR="$(find -maxdepth 1 -type d -name 'linux-*' | sort -V | tail -n 1)"
KERNEL="${KERNEL_DIR}/arch/x86/boot/bzImage"
TEST_DIR="$(dirname -- "$0")/tests"
MODULE_DIR="./modules"
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
sudo guestmount -a "$DISK_IMG" -m "$PARTITION" "$ROOTFS"
echo " done"

# Update kernel and test files
echo "* Updating kernel and test files..."
echo -n "  * "
sudo cp -v -- "$KERNEL" "${ROOTFS}/boot/vmlinuz"

if [ -d "$TEST_DIR" ]; then
    sudo cp -rv -- "${TEST_DIR}/." "${ROOTFS}/root/" | sed 's/^/  * /'
else
    echo "  * Warning: test dir $TEST_DIR not found, skipping..."
fi
echo "* Done"

# Update modules
echo "* Updating modules..."
sudo find "$MODULE_DIR" -type f -name '*.ko' -exec echo -n '   * ' \; -exec cp -v -- '{}' "${ROOTFS}/root/" \;
echo "* Done"

# Cleanup
echo -n "* Unmounting $ROOTFS..."
sync
sudo guestunmount --retry=1 -- "$ROOTFS"
rmdir -- "$ROOTFS"
echo " done"

# Run QEMU
echo
export DISK_IMG IMG_FORMAT
$(dirname -- "$0")/start-qemu.sh

ret=$?
return $ret 2> /dev/null || exit $ret
