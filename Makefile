.PHONY: format
format:
	poetry run ruff format .
	poetry run ruff check --fix .
	make clean

.PHONY: pytest
pytest:
	poetry run python -m pytest -s --capture=no ./test
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
