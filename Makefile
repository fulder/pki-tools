.PHONY: format
format:
	poetry run ruff check --fix .
	poetry run black .
	make clean

.PHONY: pytest
pytest:
	poetry run python -m pytest ./test
	make clean

.PHONY: docs-gen
docs-gen:
	cp ./docs/CNAME ./CNAME
	rm -r ./docs
	poetry run handsdown --external `git config --get remote.origin.url` --create-configs --theme=material
	poetry run mkdocs build
	rm -r ./docs
	mv ./site ./docs
	mv ./CNAME ./docs/CNAME
	rm ./docs/sitemap.xml.gz
	make clean


.PHONY: clean
clean:
	rm -rf ./htmlcov
	rm -f .coverage
	rm -rf ./.pytest_cache
	rm -rf ./.ruff_cache
	rm .readthedocs.yml
	rm mkdocs.yml
	rm requirements.mkdocs.txt