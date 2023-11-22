define relpath
$(shell realpath -m --relative-to='$(if $(2),$(2),$(CURDIR))' -- '$(1)')
endef

# Default values (can be overridden by environment variables or command line arguments)
BRANCH		?= linux-5.15.y
ROOT_DIR	?= $(shell echo "$$PWD/..")
BUILD_DIR	?= $(call relpath,$(ROOT_DIR)/build)
SCRIPT_DIR	?= $(call relpath,$(ROOT_DIR)/scripts)
KDIR		?= $(call relpath,$(ROOT_DIR)/$(BRANCH))

# Derived directories and files
SRC_DIR		:= $(shell echo "$$PWD")
SYSCALLS_H	:= $(SRC_DIR)/inc/hooked_syscalls.h
SC_DIR 		:= $(call relpath,$(SRC_DIR)/syscall_hooks)
SC_C_FILES	:= $(SC_DIR) $(shell find '$(SC_DIR)' -type f -name '*.c') # Syscall hook .c files

.PHONY: all modules clean syscalls

all: modules

$(BUILD_DIR):
	mkdir -p '$(BUILD_DIR)'

$(SYSCALLS_H): $(SC_C_FILES)
	@echo '> Generating header for hooked syscalls...'
	SRC_DIR='$(SRC_DIR)' \
		'$(SCRIPT_DIR)/gen-syscall-list.sh' '$@'
	@echo '> Hooked syscalls header generated.'

modules: $(BUILD_DIR) $(SYSCALLS_H)
	$(MAKE) -C "$(KDIR)" M="$(BUILD_DIR)" CFLAGS='$(CFLAGS)' src='$(SRC_DIR)' modules

clean: $(BUILD_DIR)
	$(MAKE) -C "$(KDIR)" M="$(BUILD_DIR)" CFLAGS='$(CFLAGS)' src='$(SRC_DIR)' clean
	rm -rf -- '$(BUILD_DIR)'

syscalls:
	@echo '> Forcing rebuild of hooked syscalls header...'
	$(MAKE) -B '$(SYSCALLS_H)' # Force rebuild
	@echo '> Hooked syscalls header rebuilt.'
