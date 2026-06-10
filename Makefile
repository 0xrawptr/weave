SHELL := /bin/zsh

APP := weave
SERVER_BIN := bin/weave-server
WORKER_BIN := /tmp/weave-worker-nocgo
CONFIG := configs/config.yaml

.PHONY: build build-server build-worker run-server run-worker start-server start-worker stop-local clean-old-tasks status test

build: build-server build-worker

build-server:
	CGO_ENABLED=0 go build -o $(SERVER_BIN) .

build-worker:
	CGO_ENABLED=0 go build -o $(WORKER_BIN) ./cmd/worker

run-server: build-server
	./$(SERVER_BIN)

run-worker: build-worker
	$(WORKER_BIN)

start-server: build-server
	nohup ./$(SERVER_BIN) </dev/null > /tmp/$(APP)-server.log 2>&1 & disown

start-worker: build-worker
	nohup $(WORKER_BIN) </dev/null > /tmp/$(APP)-worker.log 2>&1 & disown

stop-local:
	-pkill -f './$(SERVER_BIN)'
	-pkill -f '$(WORKER_BIN)'

clean-old-tasks:
	docker exec weave-postgres-1 psql -U weave -d weave -c "truncate table action_records, work_items, batch_chunks, batch_runs restart identity cascade;"

status:
	curl -sS http://127.0.0.1:18080/api/v1/work-items/summary

test:
	go test ./...
