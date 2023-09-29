#!/bin/bash

########################################################################
VERSION="5.15.133"
BRANCH="v5.x"
# LOCALVERSION="-lfs2600"
NPROC="$((`nproc` - 1))"
########################################################################

# Download kernel source
echo "* Downloading kernel source..."
if [ ! -d "linux-${VERSION}" ]; then
    wget -O- "https://cdn.kernel.org/pub/linux/kernel/${BRANCH}/linux-${VERSION}.tar.xz" | tar -xJ
fi

# Configure kernel
echo "* Configuring kernel..."
cd "linux-${VERSION}"
make defconfig
make kvm_guest.config
# ./scripts/config --set-str LOCALVERSION "${LOCALVERSION}"

# Build kernel
echo "* Building kernel..."
make -j${NPROC} bzImage
make -j${NPROC} modules

ret=$?
return $ret 2> /dev/null || exit $ret
