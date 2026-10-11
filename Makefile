COMPOSE ?= docker-compose
PYTEST_ARGS ?=

.PHONY: build test unit lint shell certs demo clean

build:
	$(COMPOSE) build app

test:
	$(COMPOSE) run --rm app pytest $(PYTEST_ARGS)

unit:
	$(COMPOSE) run --rm --no-deps app pytest -m "not integration" $(PYTEST_ARGS)

lint:
	$(COMPOSE) run --rm --no-deps app flake8 src tests

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
