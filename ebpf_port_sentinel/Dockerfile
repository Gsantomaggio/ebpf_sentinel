# Build environment for ebpf_port_sentinel. LLVM major must match the nightly rustc's LLVM,
# otherwise bpf-linker cannot read the bitcode.
FROM rust:1-trixie AS builder
ARG LLVM_VERSION=23
RUN apt-get update && apt-get install -y --no-install-recommends wget gnupg ca-certificates \
    && wget -qO /etc/apt/trusted.gpg.d/apt.llvm.org.asc https://apt.llvm.org/llvm-snapshot.gpg.key \
    && echo "deb http://apt.llvm.org/trixie/ llvm-toolchain-trixie-${LLVM_VERSION} main" > /etc/apt/sources.list.d/llvm.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends llvm-${LLVM_VERSION}-dev libpolly-${LLVM_VERSION}-dev zlib1g-dev libzstd-dev libxml2-dev
ENV LLVM_PREFIX=/usr/lib/llvm-${LLVM_VERSION}
RUN rustup toolchain install nightly --component rust-src
RUN cargo +nightly install bpf-linker --no-default-features --features llvm-${LLVM_VERSION}
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p ebpf_port_sentinel \
    && cp target/release/ebpf_port_sentinel /ebpf_port_sentinel

FROM scratch AS artifact
COPY --from=builder /ebpf_port_sentinel /ebpf_port_sentinel

# Runnable image: docker build --target runtime -t ebpf_port_sentinel .
FROM debian:trixie-slim AS runtime
COPY --from=builder /ebpf_port_sentinel /usr/local/bin/ebpf_port_sentinel
ENV RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/ebpf_port_sentinel"]

# Self-contained image: RabbitMQ + sentinel, use `docker exec` to talk to it.
#   docker build --target all-in-one -t sentinel-rabbit .
FROM debian:trixie-slim AS all-in-one
# RabbitMQ install steps from https://www.rabbitmq.com/docs/install-debian (Trixie).
# Erlang comes from Debian itself (the Team RabbitMQ Erlang repo is amd64-only).
RUN apt-get update && apt-get install -y --no-install-recommends curl gnupg apt-transport-https ca-certificates \
    && curl -1sLf "https://keys.openpgp.org/vks/v1/by-fingerprint/0A9AF2115F4687BD29803A206B73A36E6026DFCA" \
        | gpg --dearmor > /usr/share/keyrings/com.rabbitmq.team.gpg \
    && printf '%s\n' \
        'deb [signed-by=/usr/share/keyrings/com.rabbitmq.team.gpg] https://deb1.rabbitmq.com/rabbitmq-server/debian/trixie trixie main' \
        'deb [signed-by=/usr/share/keyrings/com.rabbitmq.team.gpg] https://deb2.rabbitmq.com/rabbitmq-server/debian/trixie trixie main' \
        > /etc/apt/sources.list.d/rabbitmq.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        erlang-base erlang-asn1 erlang-crypto erlang-eldap erlang-ftp erlang-inets erlang-mnesia \
        erlang-os-mon erlang-parsetools erlang-public-key erlang-runtime-tools erlang-snmp erlang-ssl \
        erlang-syntax-tools erlang-tftp erlang-tools erlang-xmerl \
    && apt-get install -y --no-install-recommends rabbitmq-server --fix-missing \
    && apt-get install -y --no-install-recommends python3 python3-venv iproute2 procps \
    && apt-get clean
# Plugins so that every protocol below has a listener: management (HTTP 15672), MQTT (1883),
# stream (5552). AMQP 0.9.1 and 1.0 are served on 5672 by core RabbitMQ.
RUN echo '[rabbitmq_management,rabbitmq_mqtt,rabbitmq_stream].' > /etc/rabbitmq/enabled_plugins \
    && chown rabbitmq:rabbitmq /etc/rabbitmq/enabled_plugins
# The stream protocol tells clients which host to reconnect to; advertise loopback so that the
# built-in `guest` user (loopback only) keeps working for clients running inside the container.
RUN echo 'stream.advertised_host = 127.0.0.1' > /etc/rabbitmq/rabbitmq.conf \
    && chown rabbitmq:rabbitmq /etc/rabbitmq/rabbitmq.conf
# Test clients: pika (AMQP 0.9.1), rabbitmq-amqp-python-client v2 (AMQP 1.0, pre-release),
# paho-mqtt, rstream.
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir pika paho-mqtt rstream rabbitmq-amqp-python-client==2.0.0rc1
COPY clients/protocol_client.py /usr/local/bin/protocol-client
RUN chmod +x /usr/local/bin/protocol-client
COPY --from=builder /ebpf_port_sentinel /usr/local/bin/ebpf_port_sentinel
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
ENV RUST_LOG=info
EXPOSE 5672
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
