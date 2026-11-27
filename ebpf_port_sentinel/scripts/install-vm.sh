#!/usr/bin/env bash
# Installs on a Debian 13 (trixie) VM what the Dockerfile provides:
#   - builder stage:    Rust (stable + nightly/rust-src), LLVM, bpf-linker
#   - all-in-one stage: RabbitMQ (+ Erlang), plugins, Python venv with the test clients
#
# Usage (from the repo, as a normal user with sudo, or as root):
#   ./scripts/install-vm.sh                 # everything
#   ./scripts/install-vm.sh --no-build      # skip the final cargo build
#   LLVM_VERSION=23 ./scripts/install-vm.sh
#
# Note: unlike the container, systemd manages RabbitMQ here (no docker/entrypoint.sh).
set -euo pipefail

LLVM_VERSION="${LLVM_VERSION:-23}"
DO_BUILD=1
[ "${1:-}" = "--no-build" ] && DO_BUILD=0

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_USER="${SUDO_USER:-$(id -un)}"
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"

if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi
as_user() { if [ "$(id -un)" = "$TARGET_USER" ]; then "$@"; else sudo -u "$TARGET_USER" -H "$@"; fi; }

. /etc/os-release
if [ "${VERSION_CODENAME:-}" != "trixie" ]; then
    echo "warning: this script targets Debian trixie, found '${PRETTY_NAME:-unknown}'" >&2
fi

export DEBIAN_FRONTEND=noninteractive
apt_install() { $SUDO apt-get install -y --no-install-recommends "$@"; }

echo "==> Base packages"
$SUDO apt-get update
apt_install wget curl gnupg apt-transport-https ca-certificates \
            build-essential pkg-config git libssl-dev

echo "==> LLVM ${LLVM_VERSION} (apt.llvm.org)"
$SUDO wget -qO /etc/apt/trusted.gpg.d/apt.llvm.org.asc https://apt.llvm.org/llvm-snapshot.gpg.key
echo "deb http://apt.llvm.org/trixie/ llvm-toolchain-trixie-${LLVM_VERSION} main" \
    | $SUDO tee /etc/apt/sources.list.d/llvm.list >/dev/null
$SUDO apt-get update
apt_install "llvm-${LLVM_VERSION}-dev" "libpolly-${LLVM_VERSION}-dev" zlib1g-dev libzstd-dev libxml2-dev

echo "==> Rust toolchains (stable + nightly with rust-src)"
CARGO_BIN="$TARGET_HOME/.cargo/bin"
if [ ! -x "$CARGO_BIN/rustup" ]; then
    as_user bash -c 'curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable'
fi
as_user "$CARGO_BIN/rustup" toolchain install nightly --component rust-src

echo "==> bpf-linker (LLVM ${LLVM_VERSION})"
as_user env PATH="$CARGO_BIN:$PATH" LLVM_PREFIX="/usr/lib/llvm-${LLVM_VERSION}" \
    cargo +nightly install bpf-linker --no-default-features --features "llvm-${LLVM_VERSION}"

echo "==> RabbitMQ + Erlang"
curl -1sLf "https://keys.openpgp.org/vks/v1/by-fingerprint/0A9AF2115F4687BD29803A206B73A36E6026DFCA" \
    | gpg --dearmor | $SUDO tee /usr/share/keyrings/com.rabbitmq.team.gpg >/dev/null
$SUDO tee /etc/apt/sources.list.d/rabbitmq.list >/dev/null <<'EOF'
deb [signed-by=/usr/share/keyrings/com.rabbitmq.team.gpg] https://deb1.rabbitmq.com/rabbitmq-server/debian/trixie trixie main
deb [signed-by=/usr/share/keyrings/com.rabbitmq.team.gpg] https://deb2.rabbitmq.com/rabbitmq-server/debian/trixie trixie main
EOF
$SUDO apt-get update
# Erlang comes from Debian itself (the Team RabbitMQ Erlang repo is amd64-only).
apt_install erlang-base erlang-asn1 erlang-crypto erlang-eldap erlang-ftp erlang-inets erlang-mnesia \
            erlang-os-mon erlang-parsetools erlang-public-key erlang-runtime-tools erlang-snmp erlang-ssl \
            erlang-syntax-tools erlang-tftp erlang-tools erlang-xmerl
apt_install rabbitmq-server --fix-missing
apt_install python3 python3-venv iproute2 procps

echo "==> RabbitMQ config (management 15672, MQTT 1883, stream 5552; AMQP on 5672)"
echo '[rabbitmq_management,rabbitmq_mqtt,rabbitmq_stream].' | $SUDO tee /etc/rabbitmq/enabled_plugins >/dev/null
$SUDO chown rabbitmq:rabbitmq /etc/rabbitmq/enabled_plugins
echo 'stream.advertised_host = 127.0.0.1' | $SUDO tee /etc/rabbitmq/rabbitmq.conf >/dev/null
$SUDO chown rabbitmq:rabbitmq /etc/rabbitmq/rabbitmq.conf
$SUDO systemctl enable rabbitmq-server
$SUDO systemctl restart rabbitmq-server

echo "==> Python test clients (/opt/venv)"
$SUDO python3 -m venv /opt/venv
$SUDO /opt/venv/bin/pip install --no-cache-dir pika paho-mqtt rstream rabbitmq-amqp-python-client==2.0.0rc1
# The script's shebang is #!/opt/venv/bin/python.
$SUDO install -m 0755 "$REPO_DIR/clients/protocol_client.py" /usr/local/bin/protocol-client

if [ "$DO_BUILD" -eq 1 ]; then
    echo "==> Building the sentinel"
    as_user env PATH="$CARGO_BIN:$PATH" bash -c "cd '$REPO_DIR' && cargo build --release -p ebpf_port_sentinel"
    $SUDO install -m 0755 "$REPO_DIR/target/release/ebpf_port_sentinel" /usr/local/bin/ebpf_port_sentinel
fi

cat <<EOF

Done.
  RabbitMQ:  systemctl status rabbitmq-server
  Sentinel:  sudo RUST_LOG=info ebpf_port_sentinel --iface lo,eth0 --port 5672,1883,5552,15672
  Clients:   protocol-client
EOF
