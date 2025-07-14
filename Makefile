BINARY_NAME=auth-service
BINARY_PATH=./bin/$(BINARY_NAME)
MAIN_PATH=./cmd/auth/main.go

all: build

build:
	@echo "Building the application..."
	@go build -o $(BINARY_PATH) $(MAIN_PATH)

run:
	@echo "Starting the application with docker-compose..."
	docker-compose up --build -d

stop:
	@echo "Stopping the application..."
	docker-compose down

sqlc:
	@echo "Generating SQLC code..."
	sqlc generate

keys:
	@echo "Generating ECDSA keys..."
	openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out jwt_private_key_pkcs8.pem
	openssl pkey -in jwt_private_key_pkcs8.pem -pubout -out jwt_public_key.pem

deps:
	@echo "Installing dependencies..."
	go mod tidy

clean:
	@echo "Cleaning up..."
	rm -f $(BINARY_PATH)

test:
	@echo "Running tests..."
	go test ./...

lint:
	@echo "Running lint"
	golangci-lint run --timeout=3m

.PHONY: all build run stop sqlc keys deps clean test help
