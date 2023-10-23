KDIR ?= $$PWD/../linux-5.15.y/

.PHONY: modules clean

modules:
	$(MAKE) -C "$(KDIR)" M="$$PWD" modules

clean:
	$(MAKE) -C "$(KDIR)" M="$$PWD" clean
