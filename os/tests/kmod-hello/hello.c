// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: GPL-2.0-only
/*
 * Smallest out-of-tree module that still exercises everything an application
 * module needs from the exported kernel build tree: the UAPI and internal
 * headers, Module.symvers (module_init/module_exit are resolved through it)
 * and the vermagic the running guest kernel will check on insmod.
 */

#include <linux/init.h>
#include <linux/module.h>

static int __init dstack_hello_init(void)
{
	pr_info("dstack-hello: loaded\n");
	return 0;
}

static void __exit dstack_hello_exit(void)
{
	pr_info("dstack-hello: unloaded\n");
}

module_init(dstack_hello_init);
module_exit(dstack_hello_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("dstack out-of-tree module build smoke test");
