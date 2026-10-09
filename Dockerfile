FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS development

WORKDIR /app

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_ROOT_USER_ACTION=ignore \
    XDG_CACHE_HOME=/tmp/.cache \
    PYTHONNOUSERSITE=1

# PYTHONNOUSERSITE=1: /app is bind-mounted from the repo in compose, so a
# stray `pip install --user` from inside a container lands in the repo's
# .local/ and silently shadows the image's hash-pinned packages across
# rebuilds (this happened with pip itself). Disabling user site-packages
# makes the image's pinned environment authoritative.

# Install pinned build tooling (hash-locked).
# Include pip/setuptools/wheel in requirements-build.txt by generating it with:
#   pip-compile --allow-unsafe --generate-hashes -o requirements-build.txt requirements-build.in
COPY requirements-build.txt /app/
# pip is hash-pinned in requirements-build.txt; it will be installed by the lockfile step below.
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install --require-hashes -r requirements-build.txt

# OS deps — upgrade first to pull in any security patches (e.g. openssl),
# then install the packages we need.
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends libatomic1 libgomp1 jq rsync \
 && rm -rf /var/lib/apt/lists/*

# Install locked Python deps (immutable)
COPY requirements.txt requirements-dev.txt /app/
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install --resume-retries 5 --require-hashes -r requirements.txt \
 && python -m pip install --resume-retries 5 --require-hashes -r requirements-dev.txt

# Now copy source and install *your* package (no dependency resolution here)
COPY canary/ /app/canary/
COPY tests/ /app/tests/
COPY data/ /app/data/
COPY pyproject.toml README.md /app/

RUN python -m pip install --no-cache-dir -e . --no-deps

# Run as a non-root user for better container security.
RUN addgroup --system appgroup \
 && adduser --system --ingroup appgroup --home /app --shell /bin/sh appuser \
 && chown -R appuser:appgroup /app
USER appuser

CMD ["python", "-m", "canary.webapp"]

# ---------------------------------------------------------------------------
# Runtime stage: the image Render deploys and CI scans.
#
# Built from the base image rather than from the development stage so that
# only the application's locked runtime dependencies (requirements.txt) are
# present. The development stage additionally carries requirements-dev.txt
# (pytest, ruff, pyright, bandit, pip-audit, pip-tools, pre-commit, mutmut,
# atheris, matplotlib and their transitive dependencies), the test suite and
# jq; none of that is needed to serve the web console or run the CLI, and
# every package shipped is attack surface a container scanner has to track.
#
# pip is needed to perform the hash-checked install and is removed afterwards:
# its vendored dependencies are indexed by scanners and can carry findings
# independent of the application's pins.
# ---------------------------------------------------------------------------
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS runtime

WORKDIR /app

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_ROOT_USER_ACTION=ignore \
    XDG_CACHE_HOME=/tmp/.cache \
    PYTHONNOUSERSITE=1

# Pinned build tooling (hash-locked), so the runtime install is verified by
# the same pip/setuptools/wheel versions as the development stage.
COPY requirements-build.txt /app/
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install --require-hashes -r requirements-build.txt

# OS deps: libatomic1/libgomp1 for xgboost and lightgbm; rsync for the data
# synchronisation to the Render persistent disk (see DEPLOYMENT.md). jq is a
# Makefile convenience and stays in the development stage only.
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends libatomic1 libgomp1 rsync \
 && rm -rf /var/lib/apt/lists/*

# Locked runtime deps only.
COPY requirements.txt /app/
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install --resume-retries 5 --require-hashes -r requirements.txt

# Application source (no tests), installed without dependency resolution.
COPY canary/ /app/canary/
COPY data/ /app/data/
COPY pyproject.toml README.md /app/
RUN python -m pip install --no-cache-dir -e . --no-deps

# Drop the installer now that the environment is final.
RUN python -m pip uninstall --yes pip wheel

RUN addgroup --system appgroup \
 && adduser --system --ingroup appgroup --home /app --shell /bin/sh appuser \
 && chown -R appuser:appgroup /app
USER appuser

CMD ["python", "-m", "canary.webapp"]
