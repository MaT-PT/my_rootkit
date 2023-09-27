KDIR ?= /home/mat/git/kernel/scripts/linux-5.15.y/
SRCDIR = src/

.PHONY: modules clean

modules:
	$(MAKE) -C "$(SRCDIR)" modules
	mkdir -p modules
	cp src/*.ko modules/

clean:
	$(MAKE) -C "$(SRCDIR)" clean
	$(MAKE) -C "$(KDIR)" M="$$PWD" clean
	rm -rf modules
