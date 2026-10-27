dev:
	uvicorn src.main:app --reload --port 8080

db-upgrade:
	alembic upgrade head

db-downgrade:
	alembic downgrade -1

db-reset:
	alembic downgrade base && alembic upgrade head

test:
	pytest tests/ -v

lint:
	ruff check src/ tests/

fmt:
	ruff format src/ tests/
