FROM gcr.io/oss-fuzz-base/base-builder-python

# Copy your repo into the OSS-Fuzz $SRC area
COPY . $SRC/canary
WORKDIR $SRC/canary

# Copy build script into expected location
COPY .clusterfuzzlite/build.sh $SRC/
