define relpath
$(shell realpath -m --relative-to='$(CURDIR)' -- '$(1)')
endef

BRANCH		?= linux-5.15.y
ROOT_DIR	?= $(shell echo "$$PWD/..")
SRC_DIR		:= $(shell echo "$$PWD")
KDIR		:= $(call relpath,$(ROOT_DIR)/$(BRANCH))

.PHONY: modules clean

modules:
	$(MAKE) -C "$(KDIR)" M="$(SRC_DIR)" CFLAGS='$(CFLAGS)' modules

clean:
	$(MAKE) -C "$(KDIR)" M="$(SRC_DIR)" CFLAGS='$(CFLAGS)' clean
