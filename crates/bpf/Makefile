# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ShadowSocketProxy contributors

CLANG ?= clang
ARCH ?= x86
KERNEL_UAPI ?= /usr/include/$(shell uname -m)-linux-gnu
CARGO ?= cargo
WORKSPACE_ROOT := $(abspath ../..)
SOURCE := shadow-socket-proxy.bpf.c
OUTPUT ?= shadow-socket-proxy.bpf.o
RUNNER_OUTPUT ?= ssp-bpf-fixture-runner
PROFILE ?= debug
RUNNER_MANIFEST := fixture-runner/Cargo.toml
RUNNER_SOURCES := $(wildcard fixture-runner/src/*.rs)
RUNNER_ARTIFACT := $(WORKSPACE_ROOT)/target/$(PROFILE)/$(RUNNER_OUTPUT)
CARGO_PROFILE_FLAG := $(if $(filter release,$(PROFILE)),--release,)

.PHONY: all clean

all: $(OUTPUT) $(RUNNER_OUTPUT)

$(OUTPUT): $(SOURCE)
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I$(KERNEL_UAPI) -c $< -o $@

$(RUNNER_OUTPUT): $(RUNNER_MANIFEST) $(RUNNER_SOURCES) $(WORKSPACE_ROOT)/Cargo.lock
	$(CARGO) build --locked $(CARGO_PROFILE_FLAG) --manifest-path $(RUNNER_MANIFEST) --bin $(RUNNER_OUTPUT)
	cp $(RUNNER_ARTIFACT) $@

clean:
	rm -f $(OUTPUT) $(RUNNER_OUTPUT)
