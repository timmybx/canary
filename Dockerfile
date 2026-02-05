FROM python:3.11-slim

WORKDIR /app

# Nice-to-have: faster pip + fewer cache writes
ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_ROOT_USER_ACTION=ignore

# Install deps first for better caching
COPY pyproject.toml README.md /app/
RUN pip install --upgrade pip && \
    pip install -e ".[dev]"

# Copy source
COPY canary/ /app/canary/
COPY tests/ /app/tests/
COPY data/ /app/data/

# Default: show help
CMD ["canary", "--help"]
