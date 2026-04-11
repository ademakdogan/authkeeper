.PHONY: install run test lint clean docker-build docker-run docker-stop docker-clean help

# Default target
.DEFAULT_GOAL := help

# =============================================================================
# UV / LOCAL DEVELOPMENT
# =============================================================================

install: ## Install dependencies
	uv sync

run: ## Run AuthKeeper locally
	uv run authkeeper

test: ## Run tests
	uv run pytest tests/ -v

test-cov: ## Run tests with coverage
	uv run pytest tests/ -v --cov=authkeeper --cov-report=html

lint: ## Run linter (ruff)
	uv run ruff check src/

lint-fix: ## Run linter and fix issues
	uv run ruff check src/ --fix

format: ## Format code (ruff)
	uv run ruff format src/

typecheck: ## Run type checker (mypy)
	uv run mypy src/

check: lint typecheck test ## Run all checks (lint + typecheck + test)

# =============================================================================
# DOCKER
# =============================================================================

DOCKER_IMAGE := authkeeper
DOCKER_TAG := latest
DOCKER_VOLUME := authkeeper-vault

docker-build: ## Build Docker image
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

docker-run: ## Run AuthKeeper in Docker (interactive)
	docker run -it --rm \
		-v $(DOCKER_VOLUME):/home/authkeeper/.local/share/authkeeper \
		--name authkeeper-cli \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

docker-compose-run: ## Run with Docker Compose
	docker compose run --rm authkeeper

docker-stop: ## Stop running container
	docker stop authkeeper-cli 2>/dev/null || true

docker-clean: docker-stop ## Remove container and image
	docker rm authkeeper-cli 2>/dev/null || true
	docker rmi $(DOCKER_IMAGE):$(DOCKER_TAG) 2>/dev/null || true

docker-volume-backup: ## Backup vault volume to current directory
	docker run --rm \
		-v $(DOCKER_VOLUME):/data:ro \
		-v $$(pwd):/backup \
		alpine cp /data/vault.db /backup/vault_backup_$$(date +%Y%m%d_%H%M%S).db
	@echo "✓ Backup saved to vault_backup_*.db"

docker-volume-rm: ## Remove vault volume (WARNING: deletes all data!)
	@read -p "Are you sure? This will DELETE ALL DATA! [y/N] " confirm; \
	if [ "$$confirm" = "y" ]; then \
		docker volume rm $(DOCKER_VOLUME); \
		echo "✓ Volume removed"; \
	else \
		echo "Cancelled"; \
	fi

docker-shell: ## Open shell in container
	docker run -it --rm \
		-v $(DOCKER_VOLUME):/home/authkeeper/.local/share/authkeeper \
		--entrypoint /bin/bash \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

# =============================================================================
# BUILD & RELEASE
# =============================================================================

build: ## Build package
	uv build

clean: ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info/
	rm -rf .pytest_cache/ .ruff_cache/ .mypy_cache/
	rm -rf htmlcov/ .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# =============================================================================
# HELP
# =============================================================================

help: ## Show this help message
	@echo "AuthKeeper - Makefile Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
