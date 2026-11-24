#!/usr/bin/env bash
# Runs inside the QEMU guest (or any root shell on a sched_ext kernel).
#   tests/guest/run_all.sh [skip-ab] [skip-e2e]
# Prints one line per stage and writes build/guest-result.json.
cd "$(dirname "$0")/../.." || exit 99
REPO=$PWD
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=$REPO
export CONDUCTOR_BUILD=${CONDUCTOR_BUILD:-/tmp/cbuild}   # tmpfs: never write arch-specific binaries into the shared repo
PASS=(); FAIL=(); SKIP=()

stage() {            # stage <name> <skip-flag|-> cmd...
  local name=$1 flag=$2; shift 2
  if [ "$flag" != "-" ] && [[ " $ARGS " == *" $flag "* ]]; then SKIP+=("$name"); echo "=== SKIP $name"; return; fi
  echo "=== STAGE $name"
  if "$@"; then echo "--- $name: PASS"; PASS+=("$name"); else echo "--- $name: FAIL"; FAIL+=("$name"); fi
}
ARGS="$*"

env_check() {
  local ok=0
  echo "kernel: $(uname -srvm)"
  [ -d /sys/kernel/sched_ext ]      || { echo "no /sys/kernel/sched_ext: kernel lacks CONFIG_SCHED_CLASS_EXT"; ok=1; }
  [ -r /sys/kernel/btf/vmlinux ]    || { echo "no /sys/kernel/btf/vmlinux: need CONFIG_DEBUG_INFO_BTF"; ok=1; }
  [ -r /proc/pressure/cpu ]         || { echo "no /proc/pressure/cpu: need CONFIG_PSI"; ok=1; }
  echo "sched_ext state: $(cat /sys/kernel/sched_ext/state 2>/dev/null)"
  echo "cpus: $(nproc)   mem: $(awk '/MemTotal/{print $2" kB"}' /proc/meminfo)   arch: $(uname -m)"
  return $ok
}

build() {
  [ -f third_party/scx-include/scx/common.bpf.h ] || { echo "third_party/scx-include missing: run tools/fetch-scx-include.sh <linux-src> on the host"; return 1; }
  mkdir -p "$CONDUCTOR_BUILD"
  make -j"$(nproc)" BUILD="$CONDUCTOR_BUILD" 2>&1 | tail -25
  [ -x "$CONDUCTOR_BUILD/conductor_load" ] && [ -f "$CONDUCTOR_BUILD/scx_conductor.bpf.o" ]
}

stage env        -         env_check
stage build      -         build
stage unit       -         python3 -m unittest discover -s tests -t . 2>&1
stage loader     -         python3 tests/guest/loader_smoke.py
stage watchdog   -         python3 tests/guest/watchdog_test.py
stage ab-latency skip-ab   python3 tests/guest/ab_latency.py
stage governor   skip-e2e  python3 tests/guest/governor_e2e.py

mkdir -p "$REPO/build"
python3 - "$(uname -m)" "$(uname -r)" "${PASS[*]}" "${FAIL[*]}" "${SKIP[*]}" > "$REPO/build/guest-result.json" <<'PY'
import json, sys
a = sys.argv
print(json.dumps({"arch": a[1], "kernel": a[2], "pass": a[3].split(), "fail": a[4].split(), "skip": a[5].split()}, indent=1))
PY
cat "$REPO/build/guest-result.json"
[ ${#FAIL[@]} -eq 0 ]
