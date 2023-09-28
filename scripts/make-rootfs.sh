#!/bin/bash

########################################################################
DISK_IMG="disk.img"
DISK_QCOW2="disk.qcow2"
DISK_SIZE="512M"
ROOTFS="/tmp/my-rootfs"
KERNEL="$(ls -1 -- linux-*/arch/x86/boot/bzImage | sort -V | tail -n 1)"
HOSTNAME="lfs2600"
BANNER="$(dirname -- "$0")/banner"
SMP="$(($(nproc) / 2))"
MEM="1G"
########################################################################

echo "* Using kernel: $KERNEL"
echo

if [ -f "$DISK_IMG" ]; then
    echo -n "* Removing existing disk image file $DISK_IMG..."
    rm -- "$DISK_IMG"
    echo " done"
fi

if [ -f "$DISK_QCOW2" ]; then
    echo -n "* Removing existing QCOW2 image file $DISK_QCOW2..."
    rm -- "$DISK_QCOW2"
    echo " done"
fi

# Create disk image file
echo -n "* Creating disk image file $DISK_IMG with size $DISK_SIZE..."
truncate -s "$DISK_SIZE" -- "$DISK_IMG"
echo " done"

# Create partition table
echo -n "* Creating MSDOS partition table..."
/sbin/parted -s "$DISK_IMG" mktable msdos
echo " done"

# Create partition
echo -n "* Creating bootable EXT4 partition..."
/sbin/parted -s "$DISK_IMG" mkpart primary ext4 1 "100%"
/sbin/parted -s "$DISK_IMG" set 1 boot on
echo " done"

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

# Format partition
echo "* Formatting partition $loop_part..."
sudo mkfs.ext4 -- "$loop_part"

# Mount partition
echo -n "* Mounting partition $loop_part on $ROOTFS..."
mkdir -p -- "$ROOTFS"
sudo mount -- "$loop_part" "$ROOTFS"
echo " done"

# Install Alpine Linux
echo -n "* Installing Alpine Linux via Docker..."
docker=$(sudo docker run -t -d --rm -v "${ROOTFS}:/my-rootfs" alpine)
if [ -z "$docker" ]; then
    echo
    echo "Error: Failed to run docker"
    return 1 2> /dev/null || exit 1
fi
echo " done"

# Configure Alpine Linux
echo "* Configuring Alpine Linux..."
sudo docker exec "$docker" sh -c 'apk add openrc util-linux build-base vim python3'
# docker exec "$docker" sh -c 'apk add openrc util-linux'
sudo docker exec "$docker" sh -c "echo '${HOSTNAME}' > /etc/hostname"
sudo docker exec "$docker" sh -c 'echo "auto lo" > /etc/network/interfaces'
sudo docker exec "$docker" sh -c 'echo "iface lo inet loopback" >> /etc/network/interfaces'
sudo docker exec "$docker" sh -c 'echo "auto eth0" >> /etc/network/interfaces'
sudo docker exec "$docker" sh -c 'echo "iface eth0 inet dhcp" >> /etc/network/interfaces'
sudo docker exec "$docker" sh -c 'ln -s agetty /etc/init.d/agetty.ttyS0'
sudo docker exec "$docker" sh -c 'echo ttyS0 > /etc/securetty'
sudo docker exec "$docker" sh -c 'rc-update add agetty.ttyS0 default'
sudo docker exec "$docker" sh -c 'rc-update add root default'
sudo docker exec "$docker" sh -c 'echo "root:root" | chpasswd'
sudo docker exec "$docker" sh -c 'rc-update add devfs boot'
sudo docker exec "$docker" sh -c 'rc-update add procfs boot'
sudo docker exec "$docker" sh -c 'rc-update add sysfs boot'
sudo docker exec "$docker" sh -c 'rc-update add networking boot'

echo -n "* Copying file system..."
sudo docker exec "$docker" sh -c 'for d in bin etc lib root sbin usr; do tar c -C / "$d" | tar x -C /my-rootfs; done'
sudo docker exec "$docker" sh -c 'for dir in dev proc run sys var; do mkdir /my-rootfs/${dir}; done'
cat -- "$BANNER" | sudo tee -a -- "${ROOTFS}/etc/issue" > /dev/null
echo " done"

# Stop Docker container
echo -n "* Stopping docker container $docker..."
sudo docker stop "$docker" > /dev/null
echo " done"

# Install kernel and GRUB
echo "* Installing kernel and GRUB..."
sudo mkdir -p -- "${ROOTFS}/boot/grub"
sudo cp -- "$KERNEL" "${ROOTFS}/boot/vmlinuz"
sudo tee -- "${ROOTFS}/boot/grub/grub.cfg" > /dev/null <<EOF
serial
terminal_output serial
set root=(hd0,1)
set timeout=1
menuentry "Linux2600" {
    linux /boot/vmlinuz root=/dev/sda1 console=ttyS0
}
EOF
sudo grub-install --target=i386-pc --boot-directory="${ROOTFS}/boot" -- "$loop_dev"

# Login as root automatically
sudo sed -i -n 'H;${x;s/^\n//;s/command=/agetty_options="-a root"\n&/;p;}' "${ROOTFS}/etc/init.d/agetty.ttyS0"

# Cleanup
echo -n "* Unmounting $ROOTFS and removing loop device $loop_dev..."
sync
sudo umount -f -l -- "$ROOTFS"
sudo losetup -d "$loop_dev"
echo " done"

# Convert disk image to qcow2
echo "* Converting $DISK_IMG image to $DISK_QCOW2..."
qemu-img convert -f raw -O qcow2 -p -c -W -m 16 "$DISK_IMG" "$DISK_QCOW2"
echo "Done"

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
    -drive file="${DISK_QCOW2},index=0,media=disk,format=qcow2" -nographic

ret=$?
return $ret 2> /dev/null || exit $ret
