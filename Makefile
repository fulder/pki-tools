.PHONY: format
format:
	poetry run ruff check --fix .
	poetry run black .

.PHONY: pytest
pytest:
	poetry run python -m pytest ./test

.PHONY: docs-gen
docs-gen:
	poetry run handsdown --external `git config --get remote.origin.url` --create-configs --theme=material
	poetry run mkdocs build
	rm -r ./docs
	rm .readthedocs.yml
	rm mkdocs.yml
	rm requirements.mkdocs.txt
	mv ./site ./docs
