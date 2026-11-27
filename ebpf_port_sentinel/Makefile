# Build and run the all-in-one Docker image (RabbitMQ + sentinel + protocol-client).
#
#   make build           build the image
#   make up              (re)create the container (RabbitMQ only; run after every build)
#   make sentinel        run the sentinel in the foreground (Ctrl-C stops it)
#   make test            run the protocol test client (from another terminal)
#
# Native Linux (no Docker; needs the toolchain from the README, root via sudo):
#
#   make linux-build         cargo build --release
#   make linux-sentinel      run the sentinel with sudo
#   make linux-sentinel-jev  same, with --enable_jev
#
# Override variables on the command line, e.g.  make sentinel PORTS=5672 IFACES=lo

IMAGE      ?= sentinel-rabbit
CONTAINER  ?= sr
IFACES     ?= lo,eth0
PORTS      ?= 5672,1883,5552,15672
RUST_LOG   ?= info
KEY_FILE   ?= env
TESTS      ?=

SENTINEL    = ebpf_port_sentinel --iface $(IFACES) --port $(PORTS)
LINUX_BIN   = ./target/release/ebpf_port_sentinel
LINUX_ARGS  = --iface $(IFACES) --port $(PORTS)
JEV_KEY     = $$(cat $(KEY_FILE))

.DEFAULT_GOAL := help
.PHONY: help build up down restart sentinel sentinel-jev sentinel-bg sentinel-jev-bg \
        sentinel-logs sentinel-stop test shell logs \
        linux-build linux-sentinel linux-sentinel-jev

help:
	@echo "build            build the Docker image ($(IMAGE))"
	@echo "up               (re)create the container ($(CONTAINER)); needed after a rebuild"
	@echo "down             stop and remove the container"
	@echo "restart          down + up"
	@echo "sentinel         run the sentinel in the foreground"
	@echo "sentinel-jev     same, with --enable_jev (API key read from $(KEY_FILE))"
	@echo "sentinel-bg      run the sentinel in the background, output in /var/log/sentinel.log"
	@echo "sentinel-jev-bg  same, with --enable_jev"
	@echo "sentinel-logs    follow the background sentinel's log"
	@echo "sentinel-stop    stop the background sentinel"
	@echo "test             run the protocol test client (TESTS='mqtt http' for a subset)"
	@echo "shell            open a shell in the container"
	@echo "logs             follow the container (RabbitMQ) logs"
	@echo "linux-build         native Linux: cargo build --release"
	@echo "linux-sentinel      native Linux: run the sentinel with sudo"
	@echo "linux-sentinel-jev  native Linux: same, with --enable_jev (key from $(KEY_FILE))"

build:
	docker build --target all-in-one -t $(IMAGE) .

# --privileged is needed to load XDP/eBPF programs.
up: down
	docker run -d --name $(CONTAINER) --privileged $(IMAGE)

down:
	-docker rm -f $(CONTAINER)

restart: up

sentinel:
	docker exec -it -e RUST_LOG=$(RUST_LOG) $(CONTAINER) $(SENTINEL)

sentinel-jev:
	@test -f $(KEY_FILE) || { echo "$(KEY_FILE) not found: put the TypeSafe API key in it" >&2; exit 1; }
	docker exec -it -e RUST_LOG=$(RUST_LOG) -e TYPESAFE_API_KEY="$(JEV_KEY)" $(CONTAINER) $(SENTINEL) --enable_jev

sentinel-bg:
	docker exec -d -e RUST_LOG=$(RUST_LOG) $(CONTAINER) sh -c '$(SENTINEL) > /var/log/sentinel.log 2>&1'

sentinel-jev-bg:
	@test -f $(KEY_FILE) || { echo "$(KEY_FILE) not found: put the TypeSafe API key in it" >&2; exit 1; }
	docker exec -d -e RUST_LOG=$(RUST_LOG) -e TYPESAFE_API_KEY="$(JEV_KEY)" $(CONTAINER) \
		sh -c '$(SENTINEL) --enable_jev > /var/log/sentinel.log 2>&1'

sentinel-logs:
	docker exec $(CONTAINER) tail -f /var/log/sentinel.log

sentinel-stop:
	docker exec $(CONTAINER) pkill -f "^ebpf_port_sentinel"

test:
	docker exec $(CONTAINER) protocol-client $(TESTS)

shell:
	docker exec -it $(CONTAINER) bash

logs:
	docker logs -f $(CONTAINER)

# ---- Native Linux (no Docker) ----

linux-build:
	cargo build --release

linux-sentinel: linux-build
	sudo RUST_LOG=$(RUST_LOG) $(LINUX_BIN) $(LINUX_ARGS)

linux-sentinel-jev: linux-build
	@test -f $(KEY_FILE) || { echo "$(KEY_FILE) not found: put the TypeSafe API key in it" >&2; exit 1; }
	sudo RUST_LOG=$(RUST_LOG) TYPESAFE_API_KEY="$(JEV_KEY)" $(LINUX_BIN) $(LINUX_ARGS) --enable_jev
