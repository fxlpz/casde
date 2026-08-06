.PHONY: build run test vet clean

BIN := bin/state-tracker
DB  := casde.db

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

# Atalhos para o servidor de teste local
serve:
	python3 test_server.py