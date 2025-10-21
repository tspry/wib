.PHONY: fmt lint type test sec all

fmt:
	black .
	isort .

lint:
	ruff check .

type:
	mypy .

test:
	pytest -q

sec:
	bandit -r wib

all: fmt lint type test sec
