.PHONY: help build run test vet templ tidy docker-build docker-up docker-down clean

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

build: ## Build server binary
	go build -o bin/loxtu-server ./cmd/server/

run: ## Run server locally
	go run ./cmd/server/

test: ## Run all tests
	go test ./...

vet: ## Static analysis
	go vet ./...

templ: ## Generate templ → *_templ.go
	templ generate

tidy: ## Prune go.mod
	go mod tidy

docker-build: ## Build Docker image
	docker build -t loxtu-go .

docker-up: ## Start stack (docker compose)
	docker compose -f loxtu-go.yml up -d

docker-down: ## Stop stack
	docker compose -f loxtu-go.yml down

clean: ## Remove binaries and generated templ files
	rm -rf bin/
	find . -name '*_templ.go' -type f -delete
