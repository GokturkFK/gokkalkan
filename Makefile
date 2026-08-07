.PHONY: build test lint fmt vet run migrate-up migrate-down docker-up docker-down clean

GO ?= go
GOLANGCI_LINT ?= golangci-lint
MIGRATE ?= goose
DB_DSN ?= postgres://gokkalkan:gokkalkan@localhost:5432/gokkalkan?sslmode=disable
COMPOSE_FILE ?= deployments/docker/docker-compose.yml

build:
	$(GO) build ./...

test:
	$(GO) test -race -coverprofile=coverage.txt ./...

lint:
	$(GOLANGCI_LINT) run ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

run:
	$(GO) run ./cmd/gokkalkan

migrate-up:
	$(MIGRATE) -dir migrations postgres "$(DB_DSN)" up

migrate-down:
	$(MIGRATE) -dir migrations postgres "$(DB_DSN)" down

docker-up:
	docker compose -f $(COMPOSE_FILE) up --build

docker-down:
	docker compose -f $(COMPOSE_FILE) down -v

clean:
	rm -rf bin dist coverage.txt coverage.html
