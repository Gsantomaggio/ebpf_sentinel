# ebpf_port_sentinel

Watches TCP ports (for example the ports of a RabbitMQ broker) and records the **first bytes of
every new connection**, to see which protocol each client really speaks. Optionally the bytes are
passed to a validator ([TypeSafe's Jev model](https://docs.typesafe.ai)) that checks whether the
protocol is the one expected on that port. The program only observes: it never drops or changes
traffic.

## How it works

```
 client ── TCP ──▶ network interface (eth0, lo, ...)
                          │
┌─────────────────────────▼──────────────────────────────────────────────────┐
│  KERNEL                                                                    │
│  1. XDP program (ebpf_port_sentinel-ebpf)                                  │
│     - parses Ethernet > IPv4/IPv6 > TCP                                    │
│     - keeps only packets whose destination port is in the PORTS map        │
│                                                                            │
│  2. Identify the connection                                                │
│     - key = (src addr, src port, dst addr, dst port, IP family)            │
│     - SEEN map: only the first packet that carries payload is reported;    │
│       FIN/RST removes the entry, so a reused source port is seen again     │
│     - copies the first 20 payload bytes (bpf_xdp_load_bytes)               │
│                                                                            │
│  3. Writes a ConnEvent {key, len, prefix} to the EVENTS ring buffer        │
│  4. Returns XDP_PASS: the packet goes on to the network stack              │ ──▶ RabbitMQ
└─────────────────────────┬──────────────────────────────────────────────────┘
                          │  ring buffer EVENTS (256 KiB)
┌─────────────────────────▼──────────────────────────────────────────────────┐
│  USER SPACE                                                                │
│  5. ebpf_port_sentinel (aya + tokio)                                       │
│     - loads and attaches the XDP program, fills PORTS from --port          │
│     - reads ConnEvent from the ring buffer > Connection {src, dst, bytes}  │
│     - sends it over a bounded channel (1024); when full the event is       │
│       dropped, so a slow validator never blocks the reader                 │
│                                                                            │
│  6. Validator (trait in validator.rs, up to 8 connections at a time)       │
│                                                                            │
│     LogValidator (default)         JevValidator (--enable_jev)             │
│     - logs addresses, hex + ASCII  - asks Jev 6 yes/no questions:          │
│                                      AMQP 0-9-1, AMQP 1.0, MQTT, HTTP,     │
│                                      Stream, TLS                           │
│                                    - probabilities > detected protocol     │
│                                    - compares with the port's protocol     │
│                                                                            │
│  7. Verdict > log line: MATCH, MISMATCH, UNSURE or UNCHECKED               │
└────────────────────────────────────────────────────────────────────────────┘
```

| piece | where | role |
|-------|-------|------|
| XDP program | `ebpf_port_sentinel-ebpf/src/main.rs` | filter by port, detect the first payload of a connection, copy 20 bytes |
| shared types | `ebpf_port_sentinel-common/src/lib.rs` | `ConnKey` and `ConnEvent`, the kernel ↔ user space contract |
| loader and reader | `ebpf_port_sentinel/src/main.rs` | attach XDP, read the ring buffer, feed the validator |
| validator trait | `ebpf_port_sentinel/src/validator.rs` | `Connection`, `Verdict`, `LogValidator`, concurrency limit |
| Jev validator | `ebpf_port_sentinel/src/jev.rs` | questions to Jev, protocol identification, expected protocol per port |

Limits:

- Only traffic seen after the sentinel starts is reported; older connections are not.
- IPv6 is handled when TCP follows the fixed header; packets with IPv6 extension headers and
  VLAN-tagged frames are ignored. A connection that sends no bytes is not reported.
- The kernel must be >= 5.18 (`bpf_xdp_load_bytes`).

## Docker (recommended, and the way to build on macOS)

Everything is built inside Docker, so the host needs neither Rust nor LLVM.

### Build the binary only

```shell
docker build --target artifact -o type=local,dest=dist .
```

Produces `dist/ebpf_port_sentinel` (Linux, same architecture as your Docker engine). Copy it to a
Linux host (kernel >= 5.18, needs root) and run it as described in
[Running on Linux](#running-on-linux).

### All-in-one image (RabbitMQ + sentinel)

One self-contained image: it builds the sentinel, installs RabbitMQ from the Team RabbitMQ apt
repo (https://www.rabbitmq.com/docs/install-debian), and on start runs **only RabbitMQ**. The
sentinel is started manually. You only interact with the container through `docker exec`.

```shell
docker build --target all-in-one -t sentinel-rabbit .
docker run -d --name sr --privileged sentinel-rabbit     # --privileged: needed to load XDP/eBPF
docker logs -f sr                                        # RabbitMQ logs
```

A running container keeps the image it was created from. After rebuilding, recreate it
(`docker rm -f sr`, then the `docker run` above), otherwise `docker exec` still runs the old
binary and rejects new flags such as `--enable_jev` with `error: unexpected argument found`.
(`--help` is not available either: `clap` is built without its help feature, so that message
does not mean the flag is wrong.)

Start the sentinel when you want it (`-it` so Ctrl-C stops it cleanly; the XDP program is
detached when it exits):

```shell
docker exec -it sr ebpf_port_sentinel --iface lo,eth0 --port 5672,1883,5552,15672
```

`--iface` and `--port` take comma-separated lists (or repeat the flag). Set `RUST_LOG=debug` with
`docker exec -e RUST_LOG=debug ...` for more output. To keep it running in the background and
read its output later:

```shell
docker exec -d sr sh -c 'ebpf_port_sentinel --iface lo,eth0 --port 5672,1883,5552,15672 > /var/log/sentinel.log 2>&1'
docker exec sr tail -f /var/log/sentinel.log
docker exec sr pkill -f "^ebpf_port_sentinel"   # stop it (-f: the process name is cut to 15 chars)
```

Then generate traffic from another terminal (IPv4 and IPv6, e.g. `curl http://localhost:5672`):

```shell
docker exec sr python3 -c "
import socket; s = socket.create_connection(('127.0.0.1', 5672)); s.send(b'hello'); s.close()"
```

The sentinel prints one line per new connection:

```
new connection 127.0.0.1:54060 -> 127.0.0.1:5672 first 8 bytes: [41 4d 51 50 00 00 09 01] "AMQP...."
```

Other useful commands: `docker exec sr rabbitmq-diagnostics status`,
`docker exec -it sr bash`, `docker rm -f sr` to stop and remove.

Notes: the Docker engine's kernel must be >= 5.18, and nothing is exposed to the host (no `-p`).
`guest/guest` only works from localhost; create a user (`rabbitmqctl add_user`) for other clients.
The stream plugin advertises `127.0.0.1` so that `guest` keeps working for in-container clients.

### Makefile shortcuts

The `Makefile` wraps the commands above. Typical flow:

```shell
make build      # docker build --target all-in-one -t sentinel-rabbit .
make up         # (re)create the container "sr"; run it after every build
make sentinel   # run the sentinel in the foreground (Ctrl-C stops it)
make test       # in a second terminal: run protocol-client
```

| target                           | what it does                                                     |
|----------------------------------|------------------------------------------------------------------|
| `make build`                     | build the image                                                  |
| `make up` / `down` / `restart`   | create, remove or recreate the container                         |
| `make sentinel`                  | sentinel in the foreground                                       |
| `make sentinel-jev`              | same with `--enable_jev` (API key read from the `env` file)      |
| `make sentinel-bg` / `sentinel-jev-bg` | sentinel in the background, output in `/var/log/sentinel.log` |
| `make sentinel-logs`             | follow the background sentinel's log                             |
| `make sentinel-stop`             | stop the background sentinel                                     |
| `make test`                      | run `protocol-client` (all tests)                                |
| `make shell` / `make logs`       | shell in the container / follow the RabbitMQ logs                |

Variables can be overridden on the command line; the defaults are `IMAGE=sentinel-rabbit`,
`CONTAINER=sr`, `IFACES=lo,eth0`, `PORTS=5672,1883,5552,15672`, `RUST_LOG=info`, `KEY_FILE=env`:

```shell
make sentinel PORTS=5672 IFACES=lo
make test TESTS="mqtt http"          # a subset of the tests
```

`make help` lists all targets.

### Validating the protocol with Jev (`--enable_jev`)

By default the sentinel only logs. With `--enable_jev` the first bytes of every connection are also
sent to [TypeSafe](https://docs.typesafe.ai)'s Jev model, which answers one yes/no question per
protocol (AMQP 0-9-1, AMQP 1.0, MQTT, HTTP, RabbitMQ Stream, TLS). The sentinel then compares the
protocol Jev identified with the one expected on the destination port (table in
`expected_protocols` in `ebpf_port_sentinel/src/jev.rs`) and logs a `suspicious connection` warning
on a mismatch, on bytes that match no protocol, or when Jev is not sure. Ports without an entry are
only reported. **The captured bytes leave the machine when this flag is on.**

The API key is read from `TYPESAFE_API_KEY`, or else from the file given by `--jev-key-file`
(default `env`, bare key or `NAME=key`). The `env` file is git- and docker-ignored; pass it in at
run time and keep it out of the image:

```shell
docker exec -i -e TYPESAFE_API_KEY="$(cat env)" sr \
  ebpf_port_sentinel --iface lo,eth0 --port 5672,1883,5552,15672 --enable_jev
```

To keep it running in the background (the key is passed per process and is not stored in the
container):

```shell
docker exec -d -e TYPESAFE_API_KEY="$(cat env)" sr sh -c \
  'ebpf_port_sentinel --iface lo,eth0 --port 5672,1883,5552,15672 --enable_jev > /var/log/sentinel.log 2>&1'
```

Without a key the sentinel exits at startup (before attaching XDP) with
`--enable_jev needs an API key`. `--jev-model` picks the model (default `jev-latest`). If the API
call fails, the connection is logged as an error ("could not validate"), never as fine or
suspicious. Set `RUST_LOG=debug` to log the exact request payload.

Each connection produces one line with a status badge, what Jev detected, what the port expects
and the probability for every protocol, plus a `suspicious connection` warning when it is not ok:

```
✅ MATCH    127.0.0.1:43502 -> 127.0.0.1:5552: detected rabbitmq_stream (p=0.92) | port 5552 expects rabbitmq_stream [amqp_0_9_1=0.02 ... tls=0.04]
❌ MISMATCH 127.0.0.1:45552 -> 127.0.0.1:5672: detected no known protocol | port 5672 expects amqp_0_9_1/amqp_1_0 [amqp_0_9_1=0.01 ... tls=0.05]
suspicious connection 127.0.0.1:45552 -> 127.0.0.1:5672: port 5672 should carry amqp_0_9_1/amqp_1_0 but the bytes match no known protocol
```

| badge          | meaning                                                              | colour |
|----------------|----------------------------------------------------------------------|--------|
| ✅ MATCH       | the protocol is the one expected on the port                         | green  |
| ❌ MISMATCH    | a different protocol, or none at all, where one was expected         | red    |
| ⚠️ UNSURE      | Jev was not sure (probabilities between 0.3 and 0.7) or several matched | yellow |
| ℹ️ UNCHECKED   | the port has no expectation, so nothing to compare with              | blue   |

Colours are only used when the output is a terminal (`docker exec -it`) and `NO_COLOR` is not set;
logs redirected to a file keep the icons but have no escape codes.

A probability of 0.7 or more reads as yes, 0.3 or less as no, and anything in between is
"inconclusive". With `protocol-client` running against the sentinel, every real protocol is
identified on its own port and the `random` connections are flagged. MQTT is the closest call
(about 0.7 to 0.8, one run 0.62 → inconclusive). Cost: one API request per connection (six
questions each), so a busy port makes many requests. Jev is weaker on hex/binary input than on
text, and these protocols have fixed magic bytes that plain code could also match; Jev earns its
place for traffic you cannot enumerate in advance.

### Protocol test client

The image has a client that opens connections with many protocols (RabbitMQ has the management,
MQTT and stream plugins enabled so each one has a listener):

```shell
docker exec sr protocol-client                 # everything
docker exec sr protocol-client mqtt http       # a subset
docker exec sr protocol-client --host localhost random
```

| test             | protocol / library                                              | port  |
|------------------|-----------------------------------------------------------------|-------|
| `amqp091`        | AMQP 0.9.1, pika                                                | 5672  |
| `amqp10`         | AMQP 1.0, rabbitmq-amqp-python-client 2.0.0rc1 (pre-release)    | 5672  |
| `mqtt`           | MQTT 3.1.1, paho-mqtt                                           | 1883  |
| `http`           | HTTP GET/PUT/POST/DELETE on the management API                  | 15672 |
| `stream`         | RabbitMQ stream protocol, rstream                               | 5552  |
| `random`         | random unknown bytes (4 and 32) on every watched port           | all   |
| `mqtt-on-amqp`   | an MQTT CONNECT sent to the AMQP port (should be a MISMATCH)    | 5672  |
| `http-on-amqp`   | an HTTP GET sent to the AMQP port (should be a MISMATCH)        | 5672  |
| `stream-on-amqp` | a stream PeerProperties frame sent to the AMQP port (MISMATCH)  | 5672  |

Each test prints `[ OK ]` / `[FAIL]`; tests are separated by a line and a 1 second pause. With the
sentinel running, it logs what it captured for each connection, e.g. `AMQP\x00\x00\x09\x01` for
0.9.1, `AMQP\x03\x01\x00\x00` for AMQP 1.0 (SASL), `10 .. 00 04 MQTT` for MQTT, `GET /api/...` for
HTTP.

## Running on Linux

Requirements: a kernel >= 5.18 with eBPF/BTF enabled, and root (the sentinel loads an eBPF program
and attaches it to a network interface). The steps below are for Fedora (every supported release
has a recent enough kernel); other distributions need the same steps with their own package
manager. To skip the toolchain, build the binary with Docker
([Build the binary only](#build-the-binary-only)) and copy it to the host.

1. Install the build dependencies:

   ```shell
   sudo dnf install -y gcc make pkgconf-pkg-config curl git \
       zlib-devel libzstd-devel libxml2-devel libffi-devel
   curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
   . "$HOME/.cargo/env"
   rustup toolchain install stable
   rustup toolchain install nightly --component rust-src
   ```

1. Install `bpf-linker`. Its LLVM major version must match the one used by the nightly `rustc`
   (check with `rustc +nightly -vV | grep LLVM`). Install the matching development package,
   e.g. for LLVM 21 (`dnf search llvm | grep devel` lists what your release offers):

   ```shell
   sudo dnf install -y llvm21-devel
   LLVM_PREFIX=/usr/lib64/llvm21 cargo +nightly install bpf-linker \
       --no-default-features --features llvm-21
   ```

   If the default `llvm-devel` already has the right major version, use `llvm-devel` and
   `LLVM_PREFIX=/usr` instead.

1. Build and run. Cargo build scripts build the eBPF program and embed it in the binary, and
   `.cargo/config.toml` sets `sudo -E` as the runner, so `cargo run` asks for your password and
   keeps your environment:

   ```shell
   RUST_LOG=info cargo run --release -- --iface eth0 --port 5672
   ```

   Or build once and run the binary directly:

   ```shell
   cargo build --release
   sudo RUST_LOG=info ./target/release/ebpf_port_sentinel --iface eth0 --port 5672
   ```

   Use `--iface lo` to watch local traffic, or a comma-separated list such as `--iface lo,eth0`.

It logs the first 20 payload bytes of each new TCP connection to that port. To validate the
protocol with Jev add `--enable_jev` (see [Validating the protocol with
Jev](#validating-the-protocol-with-jev---enable_jev)); the key comes from `TYPESAFE_API_KEY` or the
`env` file in the current directory:

```shell
TYPESAFE_API_KEY="$(cat env)" sudo -E ./target/release/ebpf_port_sentinel \
    --iface lo,eth0 --port 5672,1883,5552,15672 --enable_jev
```

## License

With the exception of eBPF code, ebpf_port_sentinel is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
