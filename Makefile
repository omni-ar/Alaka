# Alaka -- thin entry points over scripts/verify-all.sh (all logic lives there).
# Needs bash, java and docker; runs in Git Bash on Windows and on Linux CI.

VERIFY := bash scripts/verify-all.sh

.DEFAULT_GOAL := verify-all
.PHONY: verify-all verify-tla verify-sql verify-concurrency verify-java help

verify-all: ## TLC + SQL suites + concurrency probe + ./mvnw clean verify
	$(VERIFY)

verify-tla: ## TLC: safe config passes, every unsafe config is rejected
	$(VERIFY) tla

verify-sql: ## migrations + attack suite + owner-guard suite on a scratch database
	$(VERIFY) sql

verify-concurrency: ## 20-session concurrency probe on a scratch database
	$(VERIFY) concurrency

verify-java: ## ./mvnw -B clean verify (Testcontainers; needs Docker)
	$(VERIFY) java

help: ## list targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{ printf "  %-20s %s\n", $$1, $$2 }'
