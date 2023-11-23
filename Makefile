define relpath
$(shell realpath -m --relative-to='$(if $(2),$(2),$(CURDIR))' -- '$(1)')
endef

INIT_VARS	:= $(.VARIABLES)

ROOT_DIR	:= $(shell if [ -d "$$PWD/src" ]; then echo "$$PWD"; else echo "$$PWD/.."; fi)

# Default values (can be overridden by environment variables or command line arguments)
BRANCH		?= linux-5.15.y
DISK_IMG	?= disk.img
NJOBS 		?= $(shell echo $$(( $$(nproc) + 0 )))
NLOAD		?= $(shell echo "$$(nproc) * 0.85" | bc)
BUILD_DIR	?= $(call relpath,$(ROOT_DIR)/build)
TMPDIR		?= /tmp

# Derived directories and files
SRC_DIR		:= $(call relpath,$(ROOT_DIR)/src)
MOD_DIR		:= $(call relpath,$(ROOT_DIR)/modules)
SCRIPT_DIR	:= $(call relpath,$(ROOT_DIR)/scripts)
KDIR		:= $(call relpath,$(ROOT_DIR)/$(BRANCH))
DISK_QCOW2	:= $(call relpath,$(ROOT_DIR)/$(DISK_IMG:.img=.qcow2))
DISK_IMG	:= $(call relpath,$(ROOT_DIR)/$(DISK_IMG))
KMAKEFILE	:= $(call relpath,$(KDIR)/Makefile)
CONFIG		:= $(call relpath,$(KDIR)/.config)
KVMLSYMVERS	:= $(call relpath,$(KDIR)/vmlinux.symvers)
KMODSYMVERS	:= $(call relpath,$(KDIR)/Module.symvers) $(call relpath,$(KDIR)/modules.order)
KBZIMAGE	:= $(call relpath,$(KDIR)/arch/x86/boot/bzImage)

# Options for sub-makes
OPTS_CFLAGS	:= -march=native -O2 -pipe $(shell command -v mold 2>&1 >/dev/null && echo "-fuse-ld=mold") $(CFLAGS)
OPTS		:= -j$(NJOBS) -l$(NLOAD) CFLAGS='$(strip $(OPTS_CFLAGS))' TMPDIR='$(TMPDIR)'
OPTS_KMAKE	:= $(OPTS) -C '$(KDIR)'
OPTS_MODULE	:= $(OPTS) -C '$(SRC_DIR)' BRANCH='$(BRANCH)' ROOT_DIR='$(ROOT_DIR)' \
           	   KDIR='$(call relpath,$(KDIR),$(SRC_DIR))' \
           	   SCRIPT_DIR='$(call relpath,$(SCRIPT_DIR),$(SRC_DIR))' \
           	   BUILD_DIR='$(call relpath,$(BUILD_DIR),$(SRC_DIR))'

.PHONY: all clean mrproper clone pull config kernel_vmlinux kernel_bzimage kernel_modules kernel \
        kernel_headers modules copy strip rootfs qcow2 syscalls update run vars

all: modules

%.img:
	@echo '> Making rootfs image: $@...'
	DISK_IMG='$@' \
		'$(SCRIPT_DIR)/make-rootfs.sh' --no-update
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

$(KVMLSYMVERS): $(CONFIG)
	@echo '> Building kernel vmlinux...'
	$(MAKE) $(OPTS_KMAKE) vmlinux
	@echo '> Kernel vmlinux built.'

$(KBZIMAGE): $(KVMLSYMVERS)
	@echo '> Building kernel bzImage...'
	$(MAKE) $(OPTS_KMAKE) bzImage
	@echo '> Kernel bzImage built.'

$(KMODSYMVERS): $(KVMLSYMVERS)
	@echo '> Building kernel modules...'
	$(MAKE) $(OPTS_KMAKE) modules
	@echo '> Kernel modules built.'

clean:
	@echo '> Cleaning build files...'
	$(MAKE) $(OPTS_MODULE) clean
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

kernel_bzimage: $(KBZIMAGE)

kernel_vmlinux: $(KVMLSYMVERS)

kernel_modules: $(KMODSYMVERS)

kernel: kernel_bzimage kernel_modules

kernel_headers:
	@echo '> Building kernel headers...'
	$(MAKE) $(OPTS_KMAKE) headers
	@echo '> Kernel headers built.'

rootfs: $(DISK_IMG)

qcow2: $(DISK_QCOW2)

syscalls:
	$(MAKE) $(OPTS_MODULE) syscalls

modules: $(KMODSYMVERS)
	@echo '> Building modules...'
	$(MAKE) $(OPTS_MODULE) modules
	@echo '> Modules built.'

copy: modules
	@echo '> Copying modules...'
	mkdir -p -- '$(MOD_DIR)'
	cp -v -- '$(BUILD_DIR)'/*.ko '$(MOD_DIR)'
	@echo '> Modules copied.'

strip: copy
	@echo '> Stripping modules...'
	@echo '> Before:'
	@stat -c '%n,%s B' -- '$(MOD_DIR)'/* | column -t -s, -C name='FILE NAME' -C name='SIZE',right | sed 's/^/>   /'
	strip -gxM --strip-unneeded --keep-section=.modinfo -- '$(MOD_DIR)'/*.ko
	@echo '> After:'
	@stat -c '%n,%s B' -- '$(MOD_DIR)'/* | column -t -s, -C name='FILE NAME' -C name='SIZE',right | sed 's/^/>   /'
	@echo '> Modules stripped.'

update: kernel_bzimage kernel_headers rootfs copy
	@echo '> Updating kernel image...'
	DISK_IMG='$(DISK_IMG)' KERNEL_DIR='$(KDIR)' MODULE_DIR='$(MOD_DIR)' \
		'$(SCRIPT_DIR)/update-kernel-img.sh' --no-qemu
	@echo '> Kernel image updated.'

run: update
	@echo '> Running QEMU...'
	DISK_IMG='$(DISK_IMG)' \
		'$(SCRIPT_DIR)/start-qemu.sh' --no-pause
	@echo '> QEMU exited.'

# Print all variables (for debugging)
vars:
	$(foreach v,$(filter-out $(INIT_VARS) INIT_VARS,$(.VARIABLES)), \
		$(if $(filter file,$(origin $(v))), \
			$(info $(v) = <$($(v))>)))
