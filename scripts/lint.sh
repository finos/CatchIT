#!/bin/bash
set -euxo pipefail

poetry run flake8 catchit/ tests/
poetry run isort --profile black --check --diff catchit/ tests/
poetry run black --target-version py39 --check catchit/ tests/
poetry run mypy --check catchit
