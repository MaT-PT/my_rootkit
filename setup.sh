#!/bin/bash

########################################################################
DIR="$(dirname -- "$0")"
SCRIPTS_DIR="$DIR/scripts"
########################################################################

cd "$DIR"

"$SCRIPTS_DIR/make-git-kernel.sh"

ret=$?
# If kernel build failed, exit with the same error code
if [ $ret -ne 0 ]; then
    echo "Kernel build failed with error code $ret"
    return $ret 2> /dev/null || exit $ret
fi

# Create RootFS
echo
echo "Kernel build successful, creating RootFS..."
"$SCRIPTS_DIR/make-rootfs.sh"

# # Reset terminal in case QEMU messed it up
# reset
