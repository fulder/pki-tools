.PHONY: format
format:
	uv run --group lint ruff format .
	uv run --group lint ruff check --fix .
	make clean

.PHONY: pytest
pytest:
	uv run --group test python -m pytest -s --capture=no ./test
	make clean

.PHONY: clean
clean:
	rm -rf ./htmlcov
	rm -f .coverage
	rm -rf ./.pytest_cache
	rm -rf ./.ruff_cache

.PHONY: run-examples
run-examples:
	bash ./scripts/run_examples.sh
