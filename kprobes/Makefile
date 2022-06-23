# SPDX-License-Identifier: GPL-2.0-only
# builds the kprobes example kernel modules;
# then to use one (as root):  insmod <module_name.ko>

KDIR := /lib/modules/`uname -r`/build

PWD := $(shell pwd)

obj-m := sfc_nft_lat.o

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.ko *.o *.mod.c *.mod modules.order Module.symvers
