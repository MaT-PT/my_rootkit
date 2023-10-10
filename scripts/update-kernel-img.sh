#!/bin/bash

########################################################################
DISK_IMG="disk.img"
IMG_FORMAT="raw"
ROOTFS="/tmp/my-rootfs"
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
#
# Unmount/disconnect existing loop devices
if sudo umount --force --lazy --detach-loop -- "$ROOTFS" 2> /dev/null; then
    echo "* Unmounted $ROOTFS"
fi
for loop_dev in $(losetup --associated "$DISK_IMG" | cut -d ':' -f 1); do
    sudo umount --quiet --force --lazy --detach-loop -- "${loop_dev}p1"
    echo -n "* Removing existing loop device $loop_dev..."
    if sudo losetup --detach "$loop_dev"; then
        echo " done"
    else
        ret=$?
        echo
        echo "* Error: Failed to remove loop device $loop_dev"
        return $ret 2> /dev/null || exit $ret
    fi
done

# Create loop device
echo "* Creating loop device..."
sudo losetup -Pf "$DISK_IMG"
loop_dev="$(sudo losetup --partscan --find --nooverlap --show "$DISK_IMG")"
ret=$?
if [ $ret -ne 0 -o -z "$loop_dev" ]; then
    echo "* Error: Failed to create loop device"
    if [ $ret -eq 0 ]; then
        ret=1
    fi
    return $ret 2> /dev/null || exit $ret
fi
loop_part="${loop_dev}p1"
if [ ! -b "$loop_part" ]; then
    echo "* Error: partition $loop_part does not exist"
    return 1 2> /dev/null || exit 1
fi
echo "  * Created loop device: $loop_dev, partition: $loop_part"

# Mount partition
echo -n "* Mounting partition $loop_part on $ROOTFS..."
mkdir -p -- "$ROOTFS"
sudo mount -- "$loop_part" "$ROOTFS"
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
echo -n "* Unmounting $ROOTFS and removing loop device $loop_dev..."
sync
sudo umount --force --lazy -- "$ROOTFS"
sudo losetup --detach "$loop_dev"
rmdir -- "$ROOTFS"
echo " done"

# Run QEMU
echo
export DISK_IMG IMG_FORMAT
$(dirname -- "$0")/start-qemu.sh

ret=$?
return $ret 2> /dev/null || exit $ret
