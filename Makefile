CC = gcc
obj-m += xt_xff.o
TARGETS = xt_xff.ko libxt_xff.so
KVER = $(shell uname -r)

all:$(TARGETS)
	@echo "== all done =="

clean:
	make -C /usr/src/kernels/$(KVER)/ M=$(PWD) clean
	rm -f $(TARGETS)

xt_xff.ko:xt_xff.c
	make -C /usr/src/kernels/$(KVER)/ M=$(PWD) modules

libxt_xff.so:libxt_xff.c
	$(CC) -fPIC -shared -o $@ $< -lxtables;

install:
	cp xt_xff.ko /lib/modules/$(KVER)/kernel/net/netfilter/
	cp libxt_xff.so /usr/lib64/xtables/

uninstall:
	rm -f /lib/modules/$(KVER)/kernel/net/netfilter/xt_xff.ko
	rm -f /usr/lib64/xtables/libxt_xff.so
