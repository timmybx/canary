FROM python:3.11-slim@sha256:0b23cfb7425d065008b778022a17b1551c82f8b4866ee5a7a200084b7e2eafbf

WORKDIR /app

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_ROOT_USER_ACTION=ignore

# Install build tooling.
# `requirements-build.txt` is hash-locked for regular deps; `requirements-build.in`
# carries explicit pins for unsafe tooling (pip/setuptools) that pip-compile omits
# unless generated with --allow-unsafe.
COPY requirements-build.txt requirements-build.in /app/
RUN python -m pip install --no-cache-dir --require-hashes -r requirements-build.txt \
 && python -m pip install --no-cache-dir -r requirements-build.in

# OS deps (optional: pin version if you want full immutability)
RUN apt-get update \
 && apt-get install -y --no-install-recommends libatomic1 \
 && rm -rf /var/lib/apt/lists/*

# Install locked Python deps (immutable)
COPY requirements.txt requirements-dev.txt /app/
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.txt \
 && python -m pip install --no-cache-dir --require-hashes -r requirements-dev.txt

# Now copy source and install *your* package (no dependency resolution here)
COPY canary/ /app/canary/
COPY tests/ /app/tests/
COPY data/ /app/data/
COPY pyproject.toml README.md /app/

RUN python -m pip install --no-cache-dir -e . --no-deps

CMD ["canary", "--help"]
