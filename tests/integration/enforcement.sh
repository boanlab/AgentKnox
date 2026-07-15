#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University
#
# End-to-end enforcement integration test. Builds AgentKnox, runs it against a
# synthetic "crush" session, and asserts that kernel + provenance policy
# actually block the forbidden operations. Requires: root, a kernel with BTF and
# `bpf` in /sys/kernel/security/lsm, clang+llvm-strip (to build the eBPF object).
#
# Usage:  sudo tests/integration/enforcement.sh
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

[ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 2; }
grep -qw bpf /sys/kernel/security/lsm || echo "WARN: bpf not in LSM list; enforcement will be observe-only"

echo "== build =="
make -s bpf && go build -o bin/agentknox ./cmd/agentknox || { echo "build failed"; exit 1; }

WORK="$(mktemp -d)"; POLDIR=/etc/agentknox/policies
mkdir -p "$POLDIR"
cp /bin/bash "$WORK/crush"

cat > "$POLDIR/itest.yaml" <<EOF
apiVersion: security.boanlab.com/v1
kind: AgentKnoxPolicy
metadata: {name: itest}
spec:
  selector: ["*"]
  rules:
    - {name: no-read-secret, when: {system: {op: open, path: "$WORK/secret.txt"}}, effect: Block}
    - {name: no-delete-tree, when: {system: {op: delete, dir: "$WORK/protected/"}}, effect: Block}
    - {name: no-agent-code,  when: {semantic: {taint: agent-written}, system: {op: exec}}, effect: Block}
EOF
mkdir -p "$WORK/protected"
echo secret > "$WORK/secret.txt"
echo keep   > "$WORK/protected/keep.txt"

cleanup() { kill "$DPID" 2>/dev/null; rm -f "$POLDIR/itest.yaml"; rm -rf "$WORK"; }
trap cleanup EXIT

echo "== start daemon =="
./bin/agentknox --log-level=info > "$WORK/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 20); do sleep 2; grep -q "InstallRules complete" "$WORK/daemon.log" && break; done
sleep 1

echo "== scenarios (as a synthetic 'crush' session) =="
OUT="$("$WORK/crush" -c '
sleep 1
echo "READ:";   cat '"$WORK"'/secret.txt >/dev/null 2>&1 && echo read-ok || echo read-blocked
echo "DELETE:"; rm -f '"$WORK"'/protected/keep.txt 2>/dev/null; [ -f '"$WORK"'/protected/keep.txt ] && echo delete-blocked || echo delete-ok
echo "TAINT-DIRECT:"; printf "#!/bin/bash\necho x\n" > '"$WORK"'/run; chmod +x '"$WORK"'/run; sleep 1.5; '"$WORK"'/run >/dev/null 2>&1 && echo exec-ran || echo exec-blocked
echo "TAINT-COPY:"; cp '"$WORK"'/run '"$WORK"'/run2 2>/dev/null && ( sleep 1.5; '"$WORK"'/run2 >/dev/null 2>&1 && echo copy-ran || echo copy-blocked ) || echo copy-blocked
echo "TAINT-HARDLINK:"; ln '"$WORK"'/run '"$WORK"'/hl 2>/dev/null && ( sleep 1.5; '"$WORK"'/hl >/dev/null 2>&1 && echo hardlink-ran || echo hardlink-blocked ) || echo hardlink-blocked
echo "TAINT-RENAME:"; printf "#!/bin/bash\necho x\n" > '"$WORK"'/rn; chmod +x '"$WORK"'/rn; mv '"$WORK"'/rn '"$WORK"'/renamed; sleep 1.5; '"$WORK"'/renamed >/dev/null 2>&1 && echo rename-ran || echo rename-blocked
echo "TAINT-SYMLINK:"; ln -s '"$WORK"'/run '"$WORK"'/sym 2>/dev/null && ( sleep 1.5; '"$WORK"'/sym >/dev/null 2>&1 && echo symlink-ran || echo symlink-blocked ) || echo symlink-blocked
echo "TAINT-DISGUISE:"; printf "#!/bin/bash\necho x\n" > '"$WORK"'/note.txt; chmod +x '"$WORK"'/note.txt; sleep 1.5; '"$WORK"'/note.txt >/dev/null 2>&1 && echo disguise-ran || echo disguise-blocked
echo "TAINT-DYNAMIC:"; DP='"$WORK"'/dyn$RANDOM; cp '"$WORK"'/run "$DP" 2>/dev/null && ( sleep 1.5; "$DP" >/dev/null 2>&1 && echo dynamic-ran || echo dynamic-blocked ) || echo dynamic-blocked
' 2>&1)"

echo "$OUT" | grep -q read-blocked     && ok "credential read blocked"       || bad "credential read NOT blocked"
echo "$OUT" | grep -q delete-blocked   && ok "protected-dir delete blocked"  || bad "delete NOT blocked"
echo "$OUT" | grep -q exec-blocked     && ok "agent-written direct exec blocked" || bad "direct exec NOT blocked"
echo "$OUT" | grep -q copy-blocked     && ok "copy-evasion blocked"          || bad "copy-evasion NOT blocked"
echo "$OUT" | grep -q hardlink-blocked && ok "hardlink-alias exec blocked (inode taint)" || bad "hardlink-alias NOT blocked"
echo "$OUT" | grep -q rename-blocked   && ok "rename-alias exec blocked"        || bad "rename-alias NOT blocked"
echo "$OUT" | grep -q symlink-blocked  && ok "symlink-alias exec blocked"       || bad "symlink-alias NOT blocked"
echo "$OUT" | grep -q disguise-blocked && ok "extension-disguise exec blocked"  || bad "extension-disguise NOT blocked"
echo "$OUT" | grep -q dynamic-blocked  && ok "dynamic-path exec blocked"        || bad "dynamic-path NOT blocked"

echo "== result: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
