.PHONY: all server client jwks

server:
	@echo "Starting server..."
	@docker-compose up server --build

server_config:
	@echo "Starting server with config..."
	@docker-compose up server_config --build

client:
	@echo "Execute client..."
	@go run client/main.go

jwks:
	@echo "Fetch JWKS..."
	@curl -s http://localhost:8081/.well-known/jwks.json | jq .

format:
	@echo "Format code..."
	@go fmt ./...

test:
	@echo "Run tests..."
	@go test -v ./...
