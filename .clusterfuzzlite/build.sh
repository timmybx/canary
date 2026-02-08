#!/bin/bash -eu
# build.sh executed inside the base-builder-python container
# Expects fuzz targets named *_fuzzer.py somewhere under $SRC.

# Install locked deps (hash-locked) to avoid env/version drift.
pip3 install --no-cache-dir --require-hashes -r "requirements.txt"

# Make your source importable without installing it (avoids unpinned pip install).
export PYTHONPATH="$SRC:${PYTHONPATH:-}"

echo "SRC=$SRC"
echo "OUT=$OUT"
ls -la "$SRC" || true
ls -la "$SRC/canary" || true
find "$SRC" -maxdepth 4 -name '*_fuzzer.py' -print || true

# Build fuzzers into $OUT.
for fuzzer in $(find . -name '*_fuzzer.py'); do
  fuzzer_basename=$(basename -s .py $fuzzer)
  fuzzer_package=${fuzzer_basename}.pkg

  # Package into a standalone executable
  pyinstaller --distpath $OUT --onefile --name $fuzzer_package $fuzzer

cat > "$OUT/$fuzzer_basename" <<EOF
#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
ASAN_OPTIONS=\$ASAN_OPTIONS:symbolize=1:external_symbolizer_path=\$this_dir/llvm-symbolizer:detect_leaks=0 \\
PYTHONPATH="$SRC:\$PYTHONPATH" \\
\$this_dir/$fuzzer_package "\$@"
EOF
chmod +x "$OUT/$fuzzer_basename"

done
