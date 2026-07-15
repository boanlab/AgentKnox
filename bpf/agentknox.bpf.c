// SPDX-License-Identifier: GPL-2.0
// agentknox.bpf.c — umbrella translation unit. Textually includes every feature
// program so clang emits a single CO-RE object with one ELF section per program.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "wire.bpf.h"
#include "maps.bpf.h"
#include "helpers.bpf.h"

#include "process.bpf.c"
#include "file_io.bpf.c"
#include "file_meta.bpf.c"
#include "creds.bpf.c"
#include "network.bpf.c"
#include "semantic.bpf.c"
#include "stdio.bpf.c"
#include "enforcer.bpf.c"

char LICENSE[] SEC("license") = "GPL";
