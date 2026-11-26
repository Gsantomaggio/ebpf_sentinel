#!/bin/sh
# Starts RabbitMQ (no systemd in containers) and keeps the container alive.
# The eBPF sentinel is NOT started here: run it manually with `docker exec` (see README).
set -eu

# Ports to wait for before declaring the broker ready (AMQP, MQTT, stream, management HTTP).
READY_PORTS="5672 1883 5552 15672"

rabbit() { runuser -u rabbitmq -- "$@"; }

# RabbitMQ in the background, logging to stdout (container logs).
RABBITMQ_LOGS=- RABBITMQ_LOG_BASE=/var/log/rabbitmq rabbit rabbitmq-server &
RABBIT_PID=$!

stop() { rabbit rabbitmqctl stop >/dev/null 2>&1 || true; exit 0; }
trap stop TERM INT

echo "waiting for RabbitMQ..."
until rabbit rabbitmq-diagnostics -q ping >/dev/null 2>&1; do
    kill -0 "$RABBIT_PID" 2>/dev/null || { echo "RabbitMQ exited" >&2; exit 1; }
    sleep 1
done
for p in $READY_PORTS; do
    until rabbit rabbitmq-diagnostics -q check_port_listener "$p" >/dev/null 2>&1; do
        kill -0 "$RABBIT_PID" 2>/dev/null || { echo "RabbitMQ exited" >&2; exit 1; }
        sleep 1
    done
done
echo "RabbitMQ is up (ports: $READY_PORTS). Sentinel not started: run it with docker exec."

# Stay alive while RabbitMQ runs; exit (so Docker notices) if it dies.
while kill -0 "$RABBIT_PID" 2>/dev/null; do
    sleep 2
done
echo "RabbitMQ exited" >&2
exit 1
