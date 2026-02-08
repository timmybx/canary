#!/bin/bash -eu
# build.sh executed inside the base-builder-python container
# Expects fuzz targets named *_fuzzer.py somewhere under $SRC.

# Install your project (and any deps needed by fuzzers).
# If you have C extensions, this compiles them with sanitizer-friendly flags.

# Install locked deps (hash-locked) to avoid env/version drift.
pip3 install --no-cache-dir --require-hashes -r "$SRC/requirements.txt"

# Install your package without resolving deps.
pip3 install --no-cache-dir --no-deps "$SRC"

# Build fuzzers into $OUT.
for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
  fuzzer_basename=$(basename -s .py $fuzzer)
  fuzzer_package=${fuzzer_basename}.pkg

  # Package into a standalone executable to avoid env/version drift.
  pyinstaller --distpath $OUT --onefile --name $fuzzer_package $fuzzer

  # Execution wrapper (Python-only: do NOT LD_PRELOAD sanitizer library).
  cat > $OUT/$fuzzer_basename <<EOF
#!/bin/sh
this_dir=\$(dirname "\$0")
ASAN_OPTIONS=\$ASAN_OPTIONS:detect_leaks=0 \\
\$this_dir/$fuzzer_package "\$@"
EOF
  chmod +x $OUT/$fuzzer_basename
done
