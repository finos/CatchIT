#!/bin/bash
set -euxo pipefail

poetry run flake8 catchit/ tests/
poetry run isort --profile black --check --diff catchit/ tests/
poetry run black --target-version py36 --check catchit/ tests/
