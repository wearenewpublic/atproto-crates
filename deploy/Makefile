# Walking Club cluster — bootstrap / lifecycle helpers.
# Uses podman-compose if present, else docker compose.

SHELL := /usr/bin/env bash
COMPOSE ?= $(shell command -v podman-compose >/dev/null 2>&1 && echo podman-compose || echo "docker compose")

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: secrets
secrets: ## Generate all secrets (idempotent)
	./init/00-gen-secrets.sh

.PHONY: images
images: ## Build all container images
	./init/10-build-images.sh

.PHONY: tunnel
tunnel: ## Create the cloudflare tunnel + DNS routes (one-time)
	./init/20-create-tunnel.sh

.PHONY: config
config: ## Render cloudflared/config.yml from the template (envsubst)
	set -a; . ./.env; set +a; \
	  envsubst < cloudflared/config.yml.tmpl > cloudflared/config.yml; \
	  echo "wrote cloudflared/config.yml"

.PHONY: accounts
accounts: ## Create the test accounts on the PDSes
	./init/40-create-accounts.sh

.PHONY: up
up: secrets config ## Bring the whole cluster up
	$(COMPOSE) up -d

.PHONY: down
down: ## Stop the cluster (keep volumes)
	$(COMPOSE) down

.PHONY: nuke
nuke: ## Stop the cluster AND delete volumes
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Tail logs for all services
	$(COMPOSE) logs -f

.PHONY: ps
ps: ## Show service status
	$(COMPOSE) ps
