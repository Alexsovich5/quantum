COMPOSE ?= docker-compose
PYTEST_ARGS ?=

.PHONY: build test unit lint shell clean

build:
	$(COMPOSE) build app

test:
	$(COMPOSE) run --rm app pytest $(PYTEST_ARGS)

unit:
	$(COMPOSE) run --rm app pytest tests/unit $(PYTEST_ARGS)

lint:
	$(COMPOSE) run --rm app flake8 src tests

shell:
	$(COMPOSE) run --rm app bash

clean:
	$(COMPOSE) down
	rm -rf reports .pytest_cache .coverage
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
