# Temporary pipeline probes. NOT part of the product. Removed after diagnosis.
obj-m += hello.o hello_core.o
ccflags-y += -fno-stack-protector -fno-stack-check
ccflags-remove-y += -fsanitize=cfi -fsanitize=kcfi -fsanitize-cfi-cross-dso
