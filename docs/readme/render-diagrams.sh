#!/bin/sh
set -eu

readme_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

exec python3 "$readme_dir/render_diagrams.py"
