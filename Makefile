# cloud-service-enum — uv sync helpers
#
# Pick a cloud profile (or combine them). `make sync` installs the dev
# tooling + every cloud extra; use a narrower target for a lighter env.
#
#   make sync-aws        # dev + aws
#   make sync-azure      # dev + azure
#   make sync-gcp        # dev + gcp
#   make sync-osint      # dev + osint
#   make sync-reports    # dev + reports
#   make sync-cloud      # dev + aws + azure + gcp
#   make sync-all        # dev + everything (== [all] extra)
#   make sync            # dev only (core deps)
#   make sync-upgrade    # refresh locked versions
#   make clean           # wipe .venv + cache

PYTHON ?= python3
EXTRAS  ?=

.PHONY: sync sync-aws sync-azure sync-gcp sync-osint sync-reports sync-cloud sync-all sync-upgrade clean

sync:
	uv sync

sync-aws:
	uv sync --extra aws

sync-azure:
	uv sync --extra azure

sync-gcp:
	uv sync --extra gcp

sync-osint:
	uv sync --extra osint

sync-reports:
	uv sync --extra reports

sync-cloud:
	uv sync --extra aws --extra azure --extra gcp

sync-all:
	uv sync --all-extras

sync-upgrade:
	uv sync --upgrade

clean:
	rm -rf .venv uv.lock
