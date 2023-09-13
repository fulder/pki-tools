.PHONY: format
format:
	poetry run isort .
	poetry run black .
	poetry run flake8 .