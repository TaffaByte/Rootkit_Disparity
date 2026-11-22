# SPDX-License-Identifier: GPL-2.0
# Build for the Cross-Layer Disparity Detection project (libbpf CO-RE).
#
# Prereqs (Ubuntu 22.04+):
#   sudo apt install -y clang llvm libelf-dev libbpf-dev zlib1g-dev \
#        linux-tools-common linux-tools-generic linux-headers-$(uname -r) \
#        gcc make
#   # 'bpftool' comes from linux-tools-$(uname -r); vmlinux.h needs
#   # CONFIG_DEBUG_INFO_BTF=y (default on stock Ubuntu kernels).

OUTPUT   := build
CLANG    ?= clang
BPFTOOL  ?= bpftool
CC       ?= gcc

ARCH     := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/ppc64le/powerpc/;s/mips.*/mips/')
VMLINUX  := src/vmlinux.h

APPS     := rootkit detector

BPF_CFLAGS  := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Isrc -I$(OUTPUT)
USER_CFLAGS := -g -O2 -Wall -Isrc -I$(OUTPUT)
USER_LDLIBS := -lbpf -lelf -lz

BINS := $(addprefix $(OUTPUT)/,$(APPS))

.PHONY: all clean vmlinux
all: $(BINS)

# ---- vmlinux.h (kernel type info for CO-RE) --------------------------------
$(VMLINUX):
	@echo "  GEN   $@"
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
vmlinux: $(VMLINUX)

$(OUTPUT):
	@mkdir -p $(OUTPUT)

# ---- BPF objects -----------------------------------------------------------
$(OUTPUT)/rootkit.bpf.o: src/rootkit/rootkit.bpf.c src/common.h $(VMLINUX) | $(OUTPUT)
	@echo "  BPF   $@"
	@$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@llvm-strip -g $@

$(OUTPUT)/detector.bpf.o: src/detector/detector.bpf.c src/common.h $(VMLINUX) | $(OUTPUT)
	@echo "  BPF   $@"
	@$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@llvm-strip -g $@

# ---- skeletons -------------------------------------------------------------
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	@echo "  SKEL  $@"
	@$(BPFTOOL) gen skeleton $< > $@

# ---- userspace binaries ----------------------------------------------------
$(OUTPUT)/rootkit: src/rootkit/rootkit.c $(OUTPUT)/rootkit.skel.h | $(OUTPUT)
	@echo "  CC    $@"
	@$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDLIBS)

$(OUTPUT)/detector: src/detector/detector.c $(OUTPUT)/detector.skel.h | $(OUTPUT)
	@echo "  CC    $@"
	@$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDLIBS)

clean:
	@rm -rf $(OUTPUT)
	@echo "cleaned (src/vmlinux.h kept; 'make distclean' removes it)"

distclean: clean
	@rm -f $(VMLINUX)
