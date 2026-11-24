#!/usr/bin/env bash
# Independent-reader check for zip_stream.h: the gtest suite parses the writer's
# output itself, which cannot catch a mistake writer and parser share. This runs
# the suite with ZIP_STREAM_DUMP_DIR set, then has Python's zipfile (CRC-checked
# read of every member) and Info-ZIP `unzip -t` verify each archive.
#
#   tests/check_zip_stream.sh [--large] [path/to/zip_tests]
#
# --large adds a 4.5 GiB archive (a member over 4 GiB, entries starting past
# 4 GiB). It is written sparse, so it needs ~no disk, but every reader reads all
# 4.5 GiB, so it takes a minute or two. 7-Zip is used too when installed.
set -euo pipefail
large=0
if [ "${1:-}" = "--large" ]; then large=1; shift; fi
bin="${1:-build/zip_tests}"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
ZIP_STREAM_DUMP_DIR="$out" ZIP_STREAM_LARGE="$large" "$bin" >/dev/null
for z in "$out"/*.zip; do
  python3 -I - "$z" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as zf:
    bad = zf.testzip()          # reads every member and checks its CRC
    assert bad is None, f"CRC mismatch in {bad}"
    n = len(zf.infolist())
print(f"python zipfile: {sys.argv[1].rsplit('/',1)[-1]}: {n} entries OK")
PY
  if command -v unzip >/dev/null; then
    # NOT with UNZIP_DISABLE_ZIPBOMB_DETECTION: its overlap check is exactly
    # what caught inconsistent zip64 descriptors.
    unzip -tq "$z"
  else
    echo "unzip not installed; skipped Info-ZIP check" >&2
  fi
  if command -v 7z >/dev/null; then
    7z t "$z" >/dev/null && echo "7-Zip: ${z##*/} OK"
  fi
done
