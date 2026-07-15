# SPDX-License-Identifier: Apache-2.0
CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
OUT_DIR    ?= ../internal/sensor
OBJ        := $(OUT_DIR)/agentknox_bpfel.o
SRC        := agentknox.bpf.c
HEADERS    := wire.bpf.h maps.bpf.h helpers.bpf.h vmlinux.h
FEATURES   := process.bpf.c file_io.bpf.c file_meta.bpf.c creds.bpf.c network.bpf.c semantic.bpf.c stdio.bpf.c enforcer.bpf.c

CFLAGS := -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
	-I. -fno-stack-protector

.PHONY: all clean
all: $(OBJ)

$(OBJ): $(SRC) $(HEADERS) $(FEATURES)
	@mkdir -p $(OUT_DIR)
	$(CLANG) $(CFLAGS) -c $(SRC) -o $@.tmp
	$(LLVM_STRIP) -g $@.tmp -o $@
	@rm -f $@.tmp
	@echo "built $(OBJ)"

clean:
	rm -f $(OBJ)
