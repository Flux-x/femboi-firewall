# Femboi Firewall XDP build
BPF_CLANG   ?= clang
CXX         := g++
ARCH        ?= $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

OUT         ?= ../bin
OBJ_TARGET  := $(OUT)/femboi_xdp.o
CLI_TARGET  := $(OUT)/femboi-firewall-xdp

INSTALL_BIN ?= /usr/local/bin
INSTALL_LIB ?= /usr/lib/femboi

BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I. -I../include -fno-stack-protector -fno-jump-tables
CLI_CFLAGS := -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter -I. -I../include
CLI_LDFLAGS := -pie -Wl,-z,relro,-z,now

.PHONY: all bpf cli vmlinux check install clean

all: check bpf cli

# Check build tool dependencies
check:
	@command -v $(BPF_CLANG) >/dev/null 2>&1 || { \
		echo "[!] clang missing"; exit 1; }
	@command -v $(CXX) >/dev/null 2>&1 || { \
		echo "[!] g++ missing"; exit 1; }
	@[ -f vmlinux.h ] || { \
		echo "[*] generating vmlinux.h..."; \
		$(MAKE) --no-print-directory vmlinux; }
	@mkdir -p $(OUT)

# Generate vmlinux.h from BTF
vmlinux:
	@command -v bpftool >/dev/null 2>&1 || { \
		echo "[!] bpftool missing"; exit 1; }
	@[ -r /sys/kernel/btf/vmlinux ] || { \
		echo "[!] BTF missing in kernel"; exit 1; }
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile BPF object
bpf: $(OBJ_TARGET)

$(OBJ_TARGET): fw_xdp.c fw_common.h vmlinux.h
	@mkdir -p $(OUT)
	$(BPF_CLANG) $(BPF_CFLAGS) -c fw_xdp.c -o $@
	@command -v llvm-strip >/dev/null 2>&1 && llvm-strip -g $@ || true
	@echo "[+] $(OBJ_TARGET)"

# Compile CLI control utility
cli: $(CLI_TARGET)

$(CLI_TARGET): xdpctl.cpp xdp_maps.hpp fw_common.h ../include/fw.hpp ../src/util.cpp
	@mkdir -p $(OUT)
	$(CXX) $(CLI_CFLAGS) xdpctl.cpp ../src/util.cpp -o $@ $(CLI_LDFLAGS) -lpthread
	@echo "[+] $(CLI_TARGET)"

# Install binaries to system
install: all
	install -d $(INSTALL_BIN) $(INSTALL_LIB)
	install -m 0755 $(CLI_TARGET) $(INSTALL_BIN)/femboi-firewall-xdp
	install -m 0644 $(OBJ_TARGET) $(INSTALL_LIB)/femboi_xdp.o
	@echo "[+] installed"

# Clean build artifacts
clean:
	rm -f $(OBJ_TARGET) $(CLI_TARGET)
	@echo "[+] cleaned"
