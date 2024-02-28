.PHONY: format
format:
	poetry run ruff format .
	make clean

.PHONY: pytest
pytest:
	poetry run python -m pytest -s --capture=no ./test
	make clean

.PHONY: docs-gen
docs-gen:
	cp ./README.md ./HANDSDOWN.md
	cp ./docs/CNAME ./CNAME
	rm -r ./docs
	poetry run handsdown --external `git config --get remote.origin.url` --create-configs --theme=material
	poetry run mkdocs build
	rm -r ./docs
	mv ./site ./docs
	mv ./CNAME ./docs/CNAME
	rm ./docs/sitemap.xml.gz
	make clean
	rm ./HANDSDOWN.md


.PHONY: clean
clean:
	rm -rf ./htmlcov
	rm -f .coverage
	rm -rf ./.pytest_cache
	rm -rf ./.ruff_cache
	rm .readthedocs.yml
	rm mkdocs.yml
	rm requirements.mkdocs.txt