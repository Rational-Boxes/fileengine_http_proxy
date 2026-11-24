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
# 4.5 GiB, so it takes a minute or two. 7-Zip, and Java's two readers (the
# streaming ZipInputStream, which refuses STORED entries with a data descriptor
# and is why files are written as level-0 deflate, and ZipFile), are used too
# when installed.
set -euo pipefail
large=0
if [ "${1:-}" = "--large" ]; then large=1; shift; fi
bin="${1:-build/zip_tests}"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
ZIP_STREAM_DUMP_DIR="$out" ZIP_STREAM_LARGE="$large" "$bin" >/dev/null
java_src="$(mktemp -d)"
trap 'rm -rf "$out" "$java_src"' EXIT
cat > "$java_src/CheckZip.java" <<'JAVA'
import java.io.*;
import java.util.*;
import java.util.zip.*;
public class CheckZip {
    public static void main(String[] a) throws Exception {
        byte[] buf = new byte[1 << 16];
        Map<String, Long> streamed = new HashMap<>();
        try (ZipInputStream in = new ZipInputStream(new BufferedInputStream(new FileInputStream(a[0]), 1 << 16))) {
            for (ZipEntry e; (e = in.getNextEntry()) != null; ) {
                CRC32 c = new CRC32(); long n = 0;
                for (int r; (r = in.read(buf)) > 0; ) { c.update(buf, 0, r); n += r; }
                if (!e.isDirectory() && e.getCrc() != c.getValue()) throw new IOException("CRC " + e.getName());
                streamed.put(e.getName(), n);
            }
        }
        try (ZipFile z = new ZipFile(a[0])) {
            if (z.size() != streamed.size()) throw new IOException("ZipFile sees " + z.size() + ", stream " + streamed.size());
            for (Enumeration<? extends ZipEntry> en = z.entries(); en.hasMoreElements(); ) {
                ZipEntry e = en.nextElement();
                if (!Long.valueOf(e.getSize()).equals(streamed.get(e.getName()))) throw new IOException("size " + e.getName());
            }
        }
        System.out.println("java ZipInputStream + ZipFile: " + new File(a[0]).getName() + ": " + streamed.size() + " entries OK");
    }
}
JAVA
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
  if command -v java >/dev/null; then
    java "$java_src/CheckZip.java" "$z"
  fi
done
