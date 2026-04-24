FROM python:3.12-slim@sha256:520153e2deb359602c9cffd84e491e3431d76e7bf95a3255c9ce9433b76ab99a

WORKDIR /app

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_ROOT_USER_ACTION=ignore \
    XDG_CACHE_HOME=/tmp/.cache

# Install pinned build tooling (hash-locked).
# Include pip/setuptools/wheel in requirements-build.txt by generating it with:
#   pip-compile --allow-unsafe --generate-hashes -o requirements-build.txt requirements-build.in
COPY requirements-build.txt /app/
RUN python -m pip install --no-cache-dir --require-hashes -r requirements-build.txt

# OS deps (optional: pin version if you want full immutability)
RUN apt-get update \
 && apt-get install -y --no-install-recommends libatomic1 libgomp1 jq \
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

# Run as a non-root user for better container security.
RUN addgroup --system appgroup && adduser --system --ingroup appgroup --home /app appuser \
 && chown -R appuser:appgroup /app
USER appuser

CMD ["canary", "--help"]
