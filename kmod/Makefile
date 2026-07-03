# SPDX-License-Identifier: GPL-2.0
# Convenience wrapper for building against the running host's headers:
#   make -C kmod
# The server-side pipeline does not use this; it invokes the kernel tree's
# build system directly with M=$(CURDIR) (see api/builder/build-kernel-module.sh).
KDIR ?= /lib/modules/$(shell uname -r)/build

default:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
