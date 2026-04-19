setup:
	@if [ ! -f .env.standalone ]; then \
		cp .env.standalone.example .env.standalone; \
		echo "✅ Created .env.standalone"; \
	fi
	@if [ ! -f .env.docker ]; then \
		cp .env.docker.example .env.docker; \
		echo "✅ Created .env.docker"; \
	fi
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "✅ Created .env"; \
	fi
	@echo "⚠️  Fill in your secrets in the .env files before running!"

up: setup
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f

restart:
	docker compose restart

clean:
	docker compose down -v