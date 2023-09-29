#!/bin/bash

########################################################################
DISK_QCOW2="disk.qcow2"
ROOTFS="/tmp/my-rootfs"
PARTITION="/dev/sda1"
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

if [ ! -f "$DISK_QCOW2" ]; then
    echo "* Error: Disk image file $DISK_QCOW2 not found"
    return 1 2> /dev/null || exit 1
fi

# Mount partition
echo -n "* Mounting partition $PARTITION from $DISK_QCOW2 on $ROOTFS..."
mkdir -p -- "$ROOTFS"
sudo guestmount -a "$DISK_QCOW2" -m "$PARTITION" "$ROOTFS"
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
    -drive file="${DISK_QCOW2},index=0,media=disk,format=qcow2" -nographic

ret=$?
return $ret 2> /dev/null || exit $ret
