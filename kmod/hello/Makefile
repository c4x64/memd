# Temporary pipeline probe: minimal hello.ko via one DDK tree.
# NOT part of the product. Removed after diagnosis.
# Mirrors the product's sanitize neutralization exactly (the probe is
# only valid if built under identical flag hygiene).
obj-m += hello.o
ccflags-y += -fno-stack-protector -fno-stack-check
ccflags-remove-y += -fsanitize=cfi -fsanitize=kcfi -fsanitize-cfi-cross-dso
