COMPOSE ?= docker-compose
PYTEST_ARGS ?=
# The app container runs as the invoking user (see docker-compose.yml).
export QUANTUM_UID ?= $(shell id -u)
export QUANTUM_GID ?= $(shell id -g)

.PHONY: build test unit lint ports-check security-check shell certs demo clean

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

# Fails if a compose service keeps capabilities, privileges or credentials it does not need.
security-check:
	$(COMPOSE) config | $(COMPOSE) run --rm -T --no-deps app python scripts/check_compose_security.py -

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
