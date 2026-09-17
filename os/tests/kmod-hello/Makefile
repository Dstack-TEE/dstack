# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: GPL-2.0-only
# Out-of-tree module build, exactly as an application would do it: point KDIR
# at the exported dstack kernel build tree and let Kbuild drive the build.
obj-m += dstack-hello.o
dstack-hello-objs := hello.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean
