startServer:
	@echo "Starting server..."
	@go run server/main.go

startClient:
	@echo "Starting client..."
	@go run client/main.go
