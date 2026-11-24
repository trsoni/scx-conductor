#!/usr/bin/env bash
# Copy the sched_ext BPF headers into third_party/scx-include. SRC is either
#   - a Linux source tree (uses tools/sched_ext/include), or
#   - a checkout of https://github.com/sched-ext/scx (uses scheds/include).
# They must match (or be compatible with) the kernel you will run: kfunc names and flag enums
# change between releases and the compat layer lives in these files. The build probes the one
# ABI difference we know about (scx_bpf_dsq_move_to_local arity); anything else shows up as a
# compile error or a verifier rejection with the real message.
set -euo pipefail
SRC=${1:?path to a linux source tree or an scx checkout}
DST="$(cd "$(dirname "$0")/.." && pwd)/third_party/scx-include"
if [ -d "$SRC/tools/sched_ext/include/scx" ]; then
  FROM="$SRC/tools/sched_ext/include"
elif [ -d "$SRC/scheds/include/scx" ]; then
  FROM="$SRC/scheds/include"
else
  echo "found neither $SRC/tools/sched_ext/include/scx nor $SRC/scheds/include/scx" >&2
  exit 1
fi
rm -rf "$DST"
mkdir -p "$DST"
cp -r "$FROM/." "$DST/"
echo "scx headers: $FROM -> $DST ($(ls "$DST/scx" | wc -l) files in scx/)"
