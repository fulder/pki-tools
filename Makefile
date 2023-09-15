.PHONY: format
format:
	poetry run ruff check --fix .
	poetry run black .

.PHONY: pytest
pytest:
	poetry run python -m pytest ./test
