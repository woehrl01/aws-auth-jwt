.PHONY: all server client

server:
	@echo "Starting server..."
	@go run server/main.go

client:
	@echo "Execute client..."
	@go run client/main.go
