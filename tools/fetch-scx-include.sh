#!/usr/bin/env bash
# Copy the sched_ext BPF headers from a kernel tree into third_party/scx-include.
# They must come from the same (or a compatible) kernel you will run: kfunc names
# and flag enums change between releases and the compat layer lives in these files.
set -euo pipefail
SRC=${1:?path to linux source tree}
DST="$(cd "$(dirname "$0")/.." && pwd)/third_party/scx-include"
[ -d "$SRC/tools/sched_ext/include" ] || { echo "no $SRC/tools/sched_ext/include"; exit 1; }
rm -rf "$DST"
mkdir -p "$DST"
cp -r "$SRC/tools/sched_ext/include/." "$DST/"
echo "scx headers -> $DST ($(ls "$DST/scx" | wc -l) files in scx/)"
