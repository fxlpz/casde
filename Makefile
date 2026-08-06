.PHONY: build run test vet clean jsast-deps

BIN := bin/casde

build:
	go build -o $(BIN) ./cmd/state-tracker

run:
	go run ./cmd/state-tracker

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf bin/ *.db *.db-wal *.db-shm

# Dependência do módulo 2 (JS AST Extractor)
jsast-deps:
	npm install -g esprima