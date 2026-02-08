#!/bin/bash -eu
# build.sh executed inside the base-builder-python container
# Expects fuzz targets named *_fuzzer.py somewhere under $SRC.

# Install locked deps (hash-locked) to avoid env/version drift.
pip3 install --no-cache-dir --require-hashes -r "requirements.txt"

# Make your source importable without installing it (avoids unpinned pip install).
export PYTHONPATH="$SRC:${PYTHONPATH:-}"

# Build fuzzers into $OUT.
for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
  fuzzer_basename=$(basename -s .py $fuzzer)
  fuzzer_package=${fuzzer_basename}.pkg

  # Package into a standalone executable
  pyinstaller --distpath $OUT --onefile --name $fuzzer_package $fuzzer

  cat > $OUT/$fuzzer_basename <<EOF
#!/bin/sh
this_dir=\$(dirname "\$0")
ASAN_OPTIONS=\$ASAN_OPTIONS:detect_leaks=0 \\
PYTHONPATH="$SRC:\$PYTHONPATH" \\
\$this_dir/$fuzzer_package "\$@"
EOF
  chmod +x $OUT/$fuzzer_basename
done
