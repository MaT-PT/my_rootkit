#!/bin/bash

########################################################################
DISK_IMG="disk.img"
DISK_QCOW2="disk.qcow2"
########################################################################

if [ ! -f "$DISK_IMG" ]; then
    echo "* Error: disk image file $DISK_IMG not found"
    return 1 2> /dev/null || exit 1
fi

# Convert disk image to qcow2
echo "* Converting $DISK_IMG image to $DISK_QCOW2..."
qemu-img convert -f raw -O qcow2 -p -c -W -m 16 "$DISK_IMG" "$DISK_QCOW2"
echo "* Done"
