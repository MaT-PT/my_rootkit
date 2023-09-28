#!/bin/bash

########################################################################
DISK_IMG="disk.img"
ROOTFS="/tmp/my-rootfs"
KERNEL_DIR="$(find -maxdepth 1 -type d -name 'linux-*' | sort -V | tail -n 1)"
KERNEL="${KERNEL_DIR}/arch/x86/boot/bzImage"
TEST_C="$(dirname -- "$0")/test.c"
SMP="$(($(nproc) / 2))"
MEM="1G"
########################################################################

echo "* Using kernel: $KERNEL"
echo

# sudo guestmount -a disk.qcow2 -m /dev/sda1 /tmp/my-rootfs

if [ ! -f "$DISK_IMG" ]; then
    echo "* Error: disk image file $DISK_IMG not found"
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
            echo "Error: Failed to remove loop device $loop_dev"
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

# Update kernel and test.c
echo -n "* Updating kernel and test.c..."
sudo cp -- "$KERNEL" "${ROOTFS}/boot/vmlinuz"
sudo cp -- "$TEST_C" "${ROOTFS}/root/"
echo " done"

# Update modules
echo "* Updating modules..."
# sudo find "${KERNEL_DIR}/my_modules/" -type f -name '*.ko' -exec echo '   * Copying {}' \; -exec cp -- '{}' "${ROOTFS}/root/" \;
sudo find "my_modules/" -type f -name '*.ko' -exec echo '   * Copying {}' \; -exec cp -- '{}' "${ROOTFS}/root/" \;
echo "Done"

# Cleanup
echo -n "* Unmounting $ROOTFS and removing loop device $loop_dev..."
sync
sudo umount -f -l -- "$ROOTFS"
sudo losetup -d "$loop_dev"
echo " done"

# Run QEMU
if grep -E 'svm|vmx' /proc/cpuinfo > /dev/null && lsmod | grep '^kvm' > /dev/null; then
    msg="* Running QEMU with KVM..."
    args=( -enable-kvm -cpu host )
else
    msg="* Running QEMU without KVM..."
    args=( )
fi
echo "$msg"
echo -n "Press [Enter] to start"
read rd
qemu-system-x86_64 "${args[@]}" -smp $SMP -m "$MEM" \
    -drive file="${DISK_IMG},index=0,media=disk,format=raw" -nographic

ret=$?
return $ret 2> /dev/null || exit $ret
