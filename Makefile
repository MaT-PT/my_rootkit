SRCDIR = src/

.PHONY: all clean

all:
	$(MAKE) -C "$(SRCDIR)" modules
	mkdir -p modules
	cp src/*.ko modules/

clean:
	$(MAKE) -C "$(SRCDIR)" clean
	rm -rf modules
