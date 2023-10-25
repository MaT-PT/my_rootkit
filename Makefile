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
	@echo '> Making rootfs image: $@...'
	DISK_IMG='$@' \
		'$(ROOT_DIR)/scripts/make-rootfs.sh' --no-update
	@echo '> Rootfs image created: $@.'

%.qcow2: %.img
	@echo '> Converting image $< to $@...'
	qemu-img convert -f raw -O qcow2 -p -c -W -m 16 '$<' '$@'
	@echo '> Qcow2 image created: $@.'

$(KMAKEFILE):
	@echo '> Cloning kernel source...'
	git clone 'git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git' \
		--depth 1 '$(KDIR)' -b '$(BRANCH)'
	@echo '> Kernel source cloned.'

$(CONFIG): $(KMAKEFILE)
	@echo '> Configuring kernel...'
	$(MAKE) $(OPTS_KMAKE) defconfig
	$(MAKE) $(OPTS_KMAKE) kvm_guest.config
	@echo '> Kernel configured.'

$(KERNEL): $(CONFIG)
	@echo '> Building kernel...'
	$(MAKE) $(OPTS_KMAKE) bzImage
	@echo '> Kernel built.'

$(KSYMVERS): $(KERNEL)
	@echo '> Building kernel modules...'
	$(MAKE) $(OPTS_KMAKE) modules
	@echo '> Kernel modules built.'

clean:
	@echo '> Cleaning build files...'
	$(MAKE) $(OPTS_MODULE) clean
	$(MAKE) $(OPTS_KMAKE) M='$(ROOT_DIR)' clean
	@echo '> Build files cleaned.'

mrproper: clean
	@echo '> Cleaning copied modules...'
	rm -rf -- '$(MOD_DIR)'
	@echo '> Copied modules cleaned.'

clone: $(KMAKEFILE)

pull: clone
	@echo '> Pulling kernel source...'
	git -C '$(KDIR)' pull
	@echo '> Kernel source pulled.'

config: $(CONFIG)

kernel: $(KERNEL)

kernel_modules: $(KSYMVERS)

rootfs: $(DISK_IMG)

qcow2: $(DISK_QCOW2)

modules: $(KSYMVERS)
	@echo '> Building modules...'
	$(MAKE) $(OPTS_MODULE) modules
	@echo '> Modules built.'

copy: modules
	@echo '> Copying modules...'
	mkdir -p -- '$(MOD_DIR)'
	cp -- '$(SRC_DIR)'/*.ko '$(MOD_DIR)'
	@echo '> Modules copied.'

update: kernel rootfs copy
	@echo '> Updating kernel image...'
	DISK_IMG='$(DISK_IMG)' KERNEL_DIR='$(KDIR)' MODULE_DIR='$(MOD_DIR)' \
		'$(ROOT_DIR)/scripts/update-kernel-img.sh' --no-qemu
	@echo '> Kernel image updated.'

run: update
	@echo '> Running QEMU...'
	DISK_IMG='$(DISK_IMG)' \
		'$(ROOT_DIR)/scripts/start-qemu.sh' --no-pause
	@echo '> QEMU exited.'

# Print all variables (for debugging)
vars:
	$(foreach v,$(filter-out $(INIT_VARS) INIT_VARS,$(.VARIABLES)), \
		$(if $(filter file,$(origin $(v))), \
			$(info $(v) = <$($(v))>)))
