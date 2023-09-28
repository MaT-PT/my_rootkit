#!/bin/bash

########################################################################
BRANCH="linux-5.15.y"
LOCALVERSION="-lfs2600"
NPROC="$((`nproc` - 1))"
########################################################################

# Download kernel source
if [ -d "$BRANCH" ]; then
    # echo "* Pulling latest kernel source..."
    # git -C "$BRANCH" pull
    echo "* Kernel source already exists, skipping..."
else
    echo "* Cloning kernel source..."
    git clone "git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git" "$BRANCH" -b "$BRANCH" --depth 1
fi

# Configure kernel
echo "* Configuring kernel..."
cd "$BRANCH"
make defconfig
make kvm_guest.config
./scripts/config --set-str LOCALVERSION "${LOCALVERSION}"

# Build kernel
echo "* Building kernel..."
make -j${NPROC} bzImage

ret=$?
return $ret 2> /dev/null || exit $ret
