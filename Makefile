.PHONY: all server client jwks

server:
	@echo "Starting server..."
	@go run server/main.go

client:
	@echo "Execute client..."
	@go run client/main.go | jq .

jwks:
	@echo "Fetch JWKS..."
	@curl -s http://localhost:8081/.well-known/jwks.json | jq .
