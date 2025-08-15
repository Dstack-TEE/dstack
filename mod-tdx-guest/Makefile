# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: © 2022 Intel Corporation
# SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>

SRC := $(shell pwd)
KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
INSTALL_MOD_PATH := $(shell pwd)/dist/

obj-m += tdx-guest.o
tdx-guest-objs := tdcall.o mod.o

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC)

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules_install

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) clean

install:
	make -C $(KDIR) M=$(PWD) modules_install INSTALL_MOD_PATH=$(INSTALL_MOD_PATH)
