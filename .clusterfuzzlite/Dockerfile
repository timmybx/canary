FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:606108d78d3798a65cced45565f979703f6deaa472d9a84383be15e0325c46b5

# Upgrade pip to match the version pinned in requirements-build.in
COPY requirements-build.txt /tmp/requirements-build.txt
RUN python3 -m pip install --no-cache-dir --require-hashes -r /tmp/requirements-build.txt

# Copy your repo into the OSS-Fuzz $SRC area
COPY . $SRC/canary
WORKDIR $SRC/canary

# Copy build script into expected location
COPY .clusterfuzzlite/build.sh $SRC/
