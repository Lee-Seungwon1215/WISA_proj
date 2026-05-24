#!/usr/bin/env bash
# Build (if needed) and enter the ctkat-dev container with the workspace mounted.
set -euo pipefail

cd "$(dirname "$0")/.."

docker compose build
docker compose run --rm ctkat-dev
