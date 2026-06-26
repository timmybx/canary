FROM python:3.12-slim-bullseye@sha256:411fa4dcfdce7e7a3057c45662beba9dcd4fa36b2e50a2bfcd6c9333e59bf0db AS python312

FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:c9b2709d99ed8f15161d29b69342c8c49e0360f99de1d160c5ba1390af0b1768

# ClusterFuzzLite's Python base image still ships Python 3.11, but this repo
# locks deps for Python 3.12 and requires shap>=0.52.0. Overlay the same
# Python 3.12 runtime used by the main project image so pip can install the
# pinned dependency set inside the fuzzing container too.
COPY --from=python312 /usr/local/bin/python /usr/local/bin/python
COPY --from=python312 /usr/local/bin/python3 /usr/local/bin/python3
COPY --from=python312 /usr/local/bin/python3.12 /usr/local/bin/python3.12
COPY --from=python312 /usr/local/include/python3.12 /usr/local/include/python3.12
COPY --from=python312 /usr/local/lib/libpython3.12.so.1.0 /usr/local/lib/libpython3.12.so.1.0
COPY --from=python312 /usr/local/lib/libpython3.so /usr/local/lib/libpython3.so
COPY --from=python312 /usr/local/lib/python3.12 /usr/local/lib/python3.12
ENV PATH="/usr/local/bin:${PATH}" \
    LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}" \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

# Upgrade pip to match the version pinned in requirements-build.in
COPY requirements-build.txt /tmp/requirements-build.txt
RUN python3 -m pip install --no-cache-dir --require-hashes -r /tmp/requirements-build.txt

# Copy your repo into the OSS-Fuzz $SRC area
COPY . $SRC/canary
WORKDIR $SRC/canary

# Copy build script into expected location
COPY .clusterfuzzlite/build.sh $SRC/
