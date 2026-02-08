FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:606108d78d3798a65cced45565f979703f6deaa472d9a84383be15e0325c46b5

# Copy your repo into the OSS-Fuzz $SRC area
COPY . $SRC/canary
WORKDIR $SRC/canary

# Copy build script into expected location
COPY .clusterfuzzlite/build.sh $SRC/
