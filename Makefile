KDIR		?= $$PWD/linux-5.15.y/
SRC_DIR		:= $$PWD/src/
MOD_DIR		:= $$PWD/modules/
DISK_IMG	:= disk.img
DISK_IMG	:= $(shell realpath --relative-to="$(CURDIR)" -- "$$PWD/"'$(DISK_IMG)')

.PHONY: modules install clean mrproper update run kernel rootfs

modules:
	$(MAKE) -C "$(SRC_DIR)" modules

install: modules
	mkdir -p -- "$(MOD_DIR)"
	cp -- "$(SRC_DIR)"/*.ko "$(MOD_DIR)"

clean:
	$(MAKE) -C "$(SRC_DIR)" clean
	$(MAKE) -C "$(KDIR)" M="$$PWD" clean

mrproper: clean
	rm -rf -- "$(MOD_DIR)"

%.img:
	DISK_IMG='$@' "$$PWD/scripts/make-rootfs.sh" --no-update

rootfs: $(DISK_IMG)

update: rootfs install
	DISK_IMG='$(DISK_IMG)' "$$PWD/scripts/update-kernel-img.sh" --no-qemu

run: update
	DISK_IMG='$(DISK_IMG)' "$$PWD/scripts/start-qemu.sh" --no-pause

kernel:
	"$$PWD/scripts/make-git-kernel.sh"
