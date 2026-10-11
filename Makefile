COMPOSE ?= docker-compose
PYTEST_ARGS ?=

.PHONY: build test unit lint ports-check shell certs demo clean

build:
	$(COMPOSE) build app

test:
	$(COMPOSE) run --rm app pytest $(PYTEST_ARGS)

unit:
	$(COMPOSE) run --rm --no-deps app pytest -m "not integration" $(PYTEST_ARGS)

lint:
	$(COMPOSE) run --rm --no-deps app flake8 src tests scripts

# Fails if the rendered compose config publishes any port beyond 127.0.0.1.
ports-check:
	$(COMPOSE) config | $(COMPOSE) run --rm -T --no-deps app python scripts/check_ports.py -

shell:
	$(COMPOSE) run --rm app bash

certs:
	$(COMPOSE) run --rm app sh scripts/gen_test_certs.sh

demo:
	$(COMPOSE) run --rm app python -m quantum_tool roadmap -c config/scan_config.docker.yml

clean:
	$(COMPOSE) down
	rm -rf reports .pytest_cache .coverage
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
