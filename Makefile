SHELL := /bin/bash
COMPOSE_FILE := deploy/docker-compose.yml

.PHONY: up down run test chaos bench lint

up:
	docker compose -f $(COMPOSE_FILE) up -d --wait

down:
	docker compose -f $(COMPOSE_FILE) down -v

lint:
	python3 -m py_compile controlplane/lease_manager.py controlplane/server.py dataplane/provisioner.py storage/audit_chain.py tests/test_exchange.py

run:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	OPA_URL=http://localhost:8181 \
	EXCHANGE_BUCKET=ix-exchange-audit-trail \
	WEBHOOK_HMAC_SECRET=local-dev-exchange-secret \
	uvicorn controlplane.server:app --host 0.0.0.0 --port 8080

test:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	OPA_URL=http://localhost:8181 \
	EXCHANGE_BUCKET=ix-exchange-audit-trail \
	WEBHOOK_HMAC_SECRET=local-dev-exchange-secret \
	python3 -m unittest discover -s tests -p "test_*.py" -v

chaos:
	python3 -m unittest tests/test_exchange.py -k test_chaos_stale_fencing_token_rejected -v

bench:
	python3 -m unittest tests/test_exchange.py -k test_bench_lease_and_audit_chain -v
