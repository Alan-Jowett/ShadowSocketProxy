# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ShadowSocketProxy contributors

CLANG ?= clang
ARCH ?= x86
KERNEL_UAPI ?= /usr/include/$(shell uname -m)-linux-gnu
SOURCE := placeholder.bpf.c
OUTPUT ?= shadow-socket-proxy.bpf.o

.PHONY: all clean

all: $(OUTPUT)

$(OUTPUT): $(SOURCE)
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I$(KERNEL_UAPI) -c $< -o $@

clean:
	rm -f $(OUTPUT)
