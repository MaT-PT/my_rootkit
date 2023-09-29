#!/bin/bash

########################################################################
DISK_IMG="disk.img"
ROOTFS="/tmp/my-rootfs"
KERNEL_DIR="$(find -maxdepth 1 -type d -name 'linux-*' | sort -V | tail -n 1)"
KERNEL="${KERNEL_DIR}/arch/x86/boot/bzImage"
TEST_DIR="$(dirname -- "$0")/tests"
MODULE_DIR="./modules"
SMP="$(($(nproc) / 2))"
MEM="1G"
########################################################################

if [ -z "$KERNEL_DIR" ]; then
    echo "* Error: Could not find kernel source directory, try running ./scripts/make-git-kernel.sh"
    return 1 2> /dev/null || exit 1
fi

if [ ! -f "$KERNEL" ]; then
    echo "* Error: Kernel file $KERNEL not found, try running ./scripts/make-git-kernel.sh"
    return 1 2> /dev/null || exit 1
fi

echo "* Using kernel: $KERNEL"
echo

if [ ! -f "$DISK_IMG" ]; then
    echo "* Error: Disk image file $DISK_IMG not found"
    return 1 2> /dev/null || exit 1
fi

# Create loop device
echo "* Creating loop device..."
while true; do
    loop_dev=$(losetup -l | grep -- "$DISK_IMG" | cut -d ' ' -f 1 | head -n 1)
    if [ -n "$loop_dev" ]; then
        sudo umount -f -l -- "$ROOTFS" 2> /dev/null
        echo -n "  * Removing existing loop device $loop_dev..."
        if sudo losetup -d "$loop_dev"; then
            echo " done"
        else
            echo
            echo "  * Error: Failed to remove loop device $loop_dev"
            return 1 2> /dev/null || exit 1
        fi
    else
        break
    fi
done

sudo losetup -Pf "$DISK_IMG"
loop_dev=$(losetup -l | grep -- "$DISK_IMG" | cut -d ' ' -f 1 | head -n 1)
if [ -z "$loop_dev" ]; then
    echo
    echo "Error: Failed to create loop device"
    return 1 2> /dev/null || exit 1
fi
loop_part="${loop_dev}p1"
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
sudo umount -f -l -- "$ROOTFS"
sudo losetup -d "$loop_dev"
echo " done"

# Run QEMU
if grep -Eq 'svm|vmx' /proc/cpuinfo > /dev/null && lsmod | grep -q '^kvm'; then
    msg="* Running QEMU with KVM..."
    args=( -enable-kvm -cpu host )
else
    msg="* Running QEMU without KVM..."
    args=( )
fi
echo
echo "$msg"
echo -n "Press [Enter] to start, or Ctrl-C to exit"
read rd
qemu-system-x86_64 "${args[@]}" -smp $SMP -m "$MEM" \
    -drive file="${DISK_IMG},index=0,media=disk,format=raw" -nographic

ret=$?
return $ret 2> /dev/null || exit $ret
