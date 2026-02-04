#!/bin/sh
set -e

pip install -e ".[dev]" >/dev/null
exec "$@"

