# SPDX-License-Identifier: GPL-2.0
# Out-of-tree module build. Invoked via KDIR (the prepared kernel tree).
ifeq ($(KDIR),)
$(error KDIR unset: point it at the built kernel tree)
endif

obj-m += rwbridge.o

ccflags-y += -fno-stack-protector -fno-stack-check -fno-builtin -mbranch-protection=standard

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean