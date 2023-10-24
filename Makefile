define relpath
$(shell realpath -m --relative-to='$(CURDIR)' -- '$(1)')
endef

INIT_VARS	:= $(.VARIABLES)

# Default values (can be overridden by environment variables or command line arguments)
BRANCH		?= linux-5.15.y
DISK_IMG	?= disk.img
NJOBS 		?= $(shell echo $$(( $$(nproc) + 1 )))

# Derived directories and files
ROOT_DIR	:= $(shell echo "$$PWD")
SRC_DIR		:= $(call relpath,$(ROOT_DIR)/src)
MOD_DIR		:= $(call relpath,$(ROOT_DIR)/modules)
KDIR		:= $(call relpath,$(ROOT_DIR)/$(BRANCH))
DISK_QCOW2	:= $(call relpath,$(ROOT_DIR)/$(DISK_IMG:.img=.qcow2))
DISK_IMG	:= $(call relpath,$(ROOT_DIR)/$(DISK_IMG))
KMAKEFILE	:= $(call relpath,$(KDIR)/Makefile)
CONFIG		:= $(call relpath,$(KDIR)/.config)
KERNEL		:= $(call relpath,$(KDIR)/arch/x86/boot/bzImage)
KSYMVERS	:= $(call relpath,$(KDIR)/Module.symvers)

# Options for sub-makes
OPTS		:= -j$(NJOBS)
OPTS_KMAKE	:= $(OPTS) -C '$(KDIR)'
OPTS_MODULE	:= $(OPTS) -C '$(SRC_DIR)' BRANCH='$(BRANCH)' ROOT_DIR='$(ROOT_DIR)'

.PHONY: all clean mrproper clone pull config kernel kernel_modules \
		modules copy rootfs qcow2 update run vars

all: modules

%.img:
	$(info > Making rootfs image: $@...)
	DISK_IMG='$@' \
		'$(ROOT_DIR)/scripts/make-rootfs.sh' --no-update
	$(info > Rootfs image created: $@.)

%.qcow2: %.img
	$(info > Converting image $< to $@...)
	qemu-img convert -f raw -O qcow2 -p -c -W -m 16 '$<' '$@'
	$(info > Qcow2 image created: $@.)

$(KMAKEFILE):
	$(info > Cloning kernel source...)
	git clone 'git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git' \
		--depth 1 '$(KDIR)' -b '$(BRANCH)'
	$(info > Kernel source cloned.)

$(CONFIG): $(KMAKEFILE)
	$(info > Configuring kernel...)
	$(MAKE) $(OPTS_KMAKE) defconfig
	$(MAKE) $(OPTS_KMAKE) kvm_guest.config
	$(info > Kernel configured.)

$(KERNEL): $(CONFIG)
	$(info > Building kernel...)
	$(MAKE) $(OPTS_KMAKE) bzImage
	$(info > Kernel built.)

$(KSYMVERS): $(KERNEL)
	$(info > Building kernel modules...)
	$(MAKE) $(OPTS_KMAKE) modules
	$(info > Kernel modules built.)

clean:
	$(info > Cleaning build files...)
	$(MAKE) $(OPTS_MODULE) clean
	$(MAKE) $(OPTS_KMAKE) M='$(ROOT_DIR)' clean
	$(info > Build files cleaned.)

mrproper: clean
	$(info > Cleaning copied modules...)
	rm -rf -- '$(MOD_DIR)'
	$(info > Copied modules cleaned.)

clone: $(KMAKEFILE)

pull: clone
	$(info > Pulling kernel source...)
	git -C '$(KDIR)' pull
	$(info > Kernel source pulled.)

config: $(CONFIG)

kernel: $(KERNEL)

kernel_modules: $(KSYMVERS)

rootfs: $(DISK_IMG)

qcow2: $(DISK_QCOW2)

modules: $(KSYMVERS)
	$(info > Building modules...)
	$(MAKE) $(OPTS_MODULE) modules
	$(info > Modules built.)

copy: modules
	$(info > Copying modules...)
	mkdir -p -- '$(MOD_DIR)'
	cp -- '$(SRC_DIR)'/*.ko '$(MOD_DIR)'
	$(info > Modules copied.)

update: kernel rootfs copy
	$(info > Updating kernel image...)
	DISK_IMG='$(DISK_IMG)' KERNEL_DIR='$(KDIR)' MODULE_DIR='$(MOD_DIR)' \
		'$(ROOT_DIR)/scripts/update-kernel-img.sh' --no-qemu
	$(info > Kernel image updated.)

run: update
	$(info > Running QEMU...)
	DISK_IMG='$(DISK_IMG)' \
		'$(ROOT_DIR)/scripts/start-qemu.sh' --no-pause
	$(info > QEMU exited.)

# Print all variables (for debugging)
vars:
	$(foreach v,$(filter-out $(INIT_VARS) INIT_VARS,$(.VARIABLES)), \
		$(if $(filter file,$(origin $(v))), \
			$(info $(v) = <$($(v))>)))
