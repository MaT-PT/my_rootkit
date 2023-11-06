INIT_VARS	:= $(.VARIABLES)

define relpath
$(shell realpath -m --relative-to='$(CURDIR)' -- '$(1)')
endef

# Default values (can be overridden by environment variables or command line arguments)
BRANCH		?= linux-5.15.y
DISK_IMG	?= disk.img
NJOBS 		?= $(shell echo $$(( $$(nproc) + 0 )))
NLOAD		?= $(shell echo "$$(nproc) * 0.85" | bc)
TMPDIR		?= /tmp/rootkit-build

# Derived directories and files
ROOT_DIR	:= $(shell echo "$$PWD")
SRC_DIR		:= $(call relpath,$(ROOT_DIR)/src)
MOD_DIR		:= $(call relpath,$(ROOT_DIR)/modules)
SCRIPT_DIR	:= $(call relpath,$(ROOT_DIR)/scripts)
KDIR		:= $(call relpath,$(ROOT_DIR)/$(BRANCH))
DISK_QCOW2	:= $(call relpath,$(ROOT_DIR)/$(DISK_IMG:.img=.qcow2))
DISK_IMG	:= $(call relpath,$(ROOT_DIR)/$(DISK_IMG))
KMAKEFILE	:= $(call relpath,$(KDIR)/Makefile)
CONFIG		:= $(call relpath,$(KDIR)/.config)
KERNEL		:= $(call relpath,$(KDIR)/arch/x86/boot/bzImage)
KSYMVERS	:= $(call relpath,$(KDIR)/Module.symvers)
SYSCALLS_H	:= $(SRC_DIR)/inc/hooked_syscalls.h
SC_C_FILES	:= $(shell find '$(SRC_DIR)/syscall_hooks' -type f -name '*.c') # Syscall hook .c files

# Options for sub-makes
OPTS_CFLAGS	:= -march=native -O2 -pipe $(shell command -v mold 2>&1 >/dev/null && echo "-fuse-ld=mold") $(CFLAGS)
OPTS		:= -j$(NJOBS) -l$(NLOAD) CFLAGS='$(strip $(OPTS_CFLAGS))' TMPDIR='$(TMPDIR)'
OPTS_KMAKE	:= $(OPTS) -C '$(KDIR)'
OPTS_MODULE	:= $(OPTS) -C '$(SRC_DIR)' BRANCH='$(BRANCH)' ROOT_DIR='$(ROOT_DIR)'

.PHONY: all clean mrproper clone pull config kernel kernel_modules \
		modules copy rootfs qcow2 syscalls update run vars FORCE

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
	mkdir -p -- '$(TMPDIR)'
	$(MAKE) $(OPTS_KMAKE) defconfig
	$(MAKE) $(OPTS_KMAKE) kvm_guest.config
	@echo '> Kernel configured.'

$(KERNEL): $(CONFIG)
	@echo '> Building kernel...'
	mkdir -p -- '$(TMPDIR)'
	$(MAKE) $(OPTS_KMAKE) bzImage
	@echo '> Kernel built.'

$(KSYMVERS): $(KERNEL)
	@echo '> Building kernel modules...'
	mkdir -p -- '$(TMPDIR)'
	$(MAKE) $(OPTS_KMAKE) modules
	@echo '> Kernel modules built.'

$(SYSCALLS_H): $(SC_C_FILES)
	@echo '> Generating header for hooked syscalls...'
	SRC_DIR='$(SRC_DIR)' \
		'$(SCRIPT_DIR)/gen-syscall-list.sh' '$@'
	@echo '> Hooked syscalls header generated.'

clean:
	@echo '> Cleaning build files...'
	mkdir -p -- '$(TMPDIR)'
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

syscalls:
	$(MAKE) -B '$(SYSCALLS_H)' # Force rebuild

modules: $(KSYMVERS) $(SYSCALLS_H)
	@echo '> Building modules...'
	mkdir -p -- '$(TMPDIR)'
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
