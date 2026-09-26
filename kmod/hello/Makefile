# Temporary pipeline probes. NOT part of the product. Removed after diagnosis.
obj-m += hello.o hello_core.o hello_nobti.o hello_noscs.o hello_nofn.o
ccflags-y += -fno-stack-protector -fno-stack-check
ccflags-remove-y += -fsanitize=cfi -fsanitize=kcfi -fsanitize-cfi-cross-dso
# per-file neutralizations (appended last: wins over DDK globals)
CFLAGS_hello_nobti.o := -mbranch-protection=none
CFLAGS_hello_noscs.o := -fno-sanitize=shadow-call-stack
CFLAGS_hello_nofn.o := -fno-function-sections -fno-data-sections
