.PHONY: format
format:
	poetry run isort .
	poetry run black .
	poetry run flake8 .

.PHONY: pytest
pytest:
	poetry run python -m pytest ./test