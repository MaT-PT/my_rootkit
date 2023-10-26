#!/bin/bash

########################################################################
DIR="$(dirname -- "$0")"
SCRIPTS_DIR="$DIR/scripts"
NPROC="$((`nproc` - 1))"
########################################################################

cd "$DIR"

# Cleanup and build modules
make -j${NPROC} clean
make -j${NPROC} modules

ret=$?
# If build failed, exit with the same error code
if [ $ret -ne 0 ]; then
    echo "Build failed with error code $ret"
    return $ret 2> /dev/null || exit $ret
fi

# Update disk image with new modules
echo
echo "Build successful, updating disk image..."
"$SCRIPTS_DIR/update-kernel-img.sh"

# # Reset terminal in case QEMU messed it up
# reset
