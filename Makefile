.PHONY: help sandbox-images up up-no-ollama down test-all eval-golden verify-audit reset-db lint

help:
	@echo "Supply Chain Guardian - Monorepo Commands"
	@echo "  make sandbox-images Build the four allowlisted sandbox images (run once)"
	@echo "  make up             Start all services (including Ollama)"
	@echo "  make up-no-ollama   Start services without local Ollama (rule fallback)"
	@echo "  make down           Stop and tear down all containers"
	@echo "  make test-all       Run unit test suite across all services"
	@echo "  make eval-golden    Run E2E evaluation against golden & red-team repos"
	@echo "  make verify-audit   Verify Ed25519 hash chain for RUN_ID (pass RUN_ID=...)"
	@echo "  make reset-db       Re-initialize database tables and purge test runs"
	@echo "  make lint           Check python code formatting and static types"

SANDBOX_IMAGE_VERSION ?= 0.1.0

sandbox-images:
	for stage in clone resolve scan verify; do 		docker build -t guardian-sandbox-$$stage:$(SANDBOX_IMAGE_VERSION) 			-f services/launcher/sandbox-images/$$stage.Dockerfile services/launcher/sandbox-images || exit 1; 	done

up:
	docker compose --profile ollama up --build -d

up-no-ollama:
	ENABLE_OLLAMA=false docker compose up --build -d web orchestrator launcher scanner-intel remediation-engine postgres

down:
	docker compose down

test-all:
	pytest packages/contracts/tests \
	       services/launcher/tests \
	       services/orchestrator/tests \
	       services/scanner-intel/tests \
	       services/remediation-engine/tests -v

eval-golden:
	python tests/eval_runner.py --suite all

verify-audit:
	python services/orchestrator/app/db/audit_chain.py --verify $(RUN_ID)

reset-db:
	docker compose exec postgres psql -U guardian -d guardian -c "TRUNCATE artifacts, findings, dependency_edges, audit_log CASCADE;"

lint:
	python -m pip install ruff black flake8 mypy -q || true
	ruff check packages services
