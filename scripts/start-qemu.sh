#!/bin/bash

########################################################################
if [ -z "$DISK_IMG" ]; then
    DISK_IMG="disk.img"
fi
if [ -z "$IMG_FORMAT" ]; then
    case "$DISK_IMG" in
        *.raw | *.img)
        IMG_FORMAT="raw" ;;

        *.qcow2)
        IMG_FORMAT="qcow2" ;;

        *)
        IMG_FORMAT="raw" ;;
    esac
fi
SMP="$(($(nproc) / 2))"
MEM="1G"
########################################################################

# Run QEMU
if grep -Eq 'svm|vmx' /proc/cpuinfo > /dev/null && lsmod | grep -q '^kvm'; then
    kvm="with"
    args=( -enable-kvm -cpu host )
else
    kvm="without"
    args=( )
fi

echo "*** STARTING LINUX MACHINE ***"
echo "* Using disk file $DISK_IMG (format: $IMG_FORMAT)"
echo "* Running QEMU $kvm KVM on $SMP cores with $MEM memory..."

if [ "$1" != "--no-pause" ]; then
    echo -n "Press [Enter] to start, or Ctrl-C to exit"
    read rd
fi
qemu-system-x86_64 "${args[@]}" -smp "$SMP" -m "$MEM" \
    -drive file="${DISK_IMG},index=0,media=disk,format=${IMG_FORMAT}" -nographic

ret=$?
return $ret 2> /dev/null || exit $ret
