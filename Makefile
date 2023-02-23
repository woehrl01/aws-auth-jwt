.PHONY: all server client jwks

server:
	@echo "Starting server..."
	@docker-compose up --build

client:
	@echo "Execute client..."
	@go run client/main.go

jwks:
	@echo "Fetch JWKS..."
	@curl -s http://localhost:8081/.well-known/jwks.json | jq .
