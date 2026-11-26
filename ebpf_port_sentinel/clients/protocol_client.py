#!/opt/venv/bin/python
"""Opens connections to the local RabbitMQ with many different protocols, so that the eBPF
sentinel has something to detect.

Usage (inside the container):
    protocol-client                  # run everything
    protocol-client mqtt http        # only these
    protocol-client --host 127.0.0.1 random

Every test opens its own TCP connection(s); the sentinel should log one line per connection with
the first bytes of that protocol's handshake.
"""

import argparse
import asyncio
import base64
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
import warnings

# pika 1.5 warns that BlockingConnection will go away in 2.0; irrelevant for this tool.
warnings.filterwarnings("ignore", category=DeprecationWarning)

USER = PASSWORD = "guest"
# Ports the sentinel watches by default (see docker/entrypoint.sh).
AMQP_PORT, MQTT_PORT, STREAM_PORT, HTTP_PORT = 5672, 1883, 5552, 15672


SEPARATOR = "─" * 72
TEST_PAUSE = 1.0  # seconds between tests


def log(msg: str) -> None:
    print(f"       {msg}", flush=True)


def resolve(host: str, port: int) -> str:
    """Addresses the host name resolves to, in the order a client will try them."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        return f"unresolvable ({e})"
    seen = []
    for family, _, _, _, addr in infos:
        text = f"[{addr[0]}]:{addr[1]}" if family == socket.AF_INET6 else f"{addr[0]}:{addr[1]}"
        if text not in seen:
            seen.append(text)
    return ", ".join(seen)


def target(proto: str, host: str, port: int, extra: str = "") -> None:
    log(f"{proto}: connecting to {host}:{port} -> {resolve(host, port)} (user={USER}){extra}")


def amqp091(host: str) -> str:
    """AMQP 0.9.1 with pika. Handshake starts with b'AMQP\\x00\\x00\\x09\\x01'."""
    import pika

    target("AMQP 0.9.1 (pika)", host, AMQP_PORT, ", queue=sentinel-091")
    conn = pika.BlockingConnection(
        pika.ConnectionParameters(host, AMQP_PORT, credentials=pika.PlainCredentials(USER, PASSWORD))
    )
    ch = conn.channel()
    ch.queue_declare("sentinel-091", durable=True)
    ch.basic_publish("", "sentinel-091", b"hello 0.9.1")
    _, _, body = ch.basic_get("sentinel-091", auto_ack=True)
    ch.queue_delete("sentinel-091")
    conn.close()
    return f"published and fetched {body!r}"


def amqp10(host: str) -> str:
    """AMQP 1.0 with rabbitmq-amqp-python-client v2. Handshake starts with b'AMQP\\x03\\x01\\x00\\x00'
    (SASL), then b'AMQP\\x00\\x01\\x00\\x00'."""
    from rabbitmq_amqp_python_client import Connection, ConnectionParameters, Message

    target("AMQP 1.0 (rabbitmq-amqp-python-client)", host, AMQP_PORT, ", queue=sentinel-10")
    conn = Connection(ConnectionParameters(host=host, port=AMQP_PORT, user=USER, password=PASSWORD))
    try:
        mgmt = conn.management()
        mgmt.queue("sentinel-10").declare()
        publisher = conn.publisher_builder().queue("sentinel-10").build()
        publisher.publish(Message("hello 1.0"))
        publisher.close()
        mgmt.queue("sentinel-10").delete()
    finally:
        conn.close()
    return "declared queue, published, deleted"


def mqtt(host: str) -> str:
    """MQTT 3.1.1 with paho. First byte is the CONNECT packet type 0x10, then b'\\x00\\x04MQTT'."""
    import paho.mqtt.client as paho

    target("MQTT (paho)", host, MQTT_PORT, ", client_id=sentinel-mqtt, topic=sentinel/test, qos=1")
    client = paho.Client(paho.CallbackAPIVersion.VERSION2, client_id="sentinel-mqtt")
    client.username_pw_set(USER, PASSWORD)
    client.connect(host, MQTT_PORT, keepalive=10)
    client.loop_start()
    try:
        info = client.publish("sentinel/test", b"hello mqtt", qos=1)
        info.wait_for_publish(timeout=5)
        if not info.is_published():
            raise RuntimeError("publish was not acknowledged")
    finally:
        client.loop_stop()
        client.disconnect()
    return "published with qos 1"


def http(host: str) -> str:
    """HTTP against the management API: GET, PUT, POST, DELETE (each is a new TCP connection)."""
    base = f"http://{host}:{HTTP_PORT}/api"
    auth = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()

    def call(method: str, path: str, body: dict | None = None) -> int:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method)
        req.add_header("Authorization", auth)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        # Connection: close so every call is a fresh TCP connection the sentinel can see.
        req.add_header("Connection", "close")
        log(f"HTTP: {method} {base}{path} -> {resolve(host, HTTP_PORT)}"
            f"{' body=' + json.dumps(body) if body is not None else ''}")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code

    statuses = {
        "GET /overview": call("GET", "/overview"),
        "PUT /queues/%2F/sentinel-http": call("PUT", "/queues/%2F/sentinel-http", {"durable": True}),
        "POST /exchanges/%2F/amq.default/publish": call(
            "POST",
            "/exchanges/%2F/amq.default/publish",
            {"properties": {}, "routing_key": "sentinel-http", "payload": "hi", "payload_encoding": "string"},
        ),
        "DELETE /queues/%2F/sentinel-http": call("DELETE", "/queues/%2F/sentinel-http"),
    }
    bad = {k: v for k, v in statuses.items() if v >= 400}
    if bad:
        raise RuntimeError(f"HTTP errors: {bad}")
    return ", ".join(f"{k} -> {v}" for k, v in statuses.items())


def stream(host: str) -> str:
    """RabbitMQ stream protocol with rstream. Binary frames, no text header."""
    from rstream import Producer

    target("stream (rstream)", host, STREAM_PORT, ", stream=sentinel-stream")

    async def run() -> None:
        async with Producer(host=host, port=STREAM_PORT, username=USER, password=PASSWORD) as producer:
            await producer.create_stream("sentinel-stream", exists_ok=True)
            try:
                # send() only queues the message; send_wait() returns once the broker confirmed
                # it, so the stream is not deleted underneath a pending publish.
                await producer.send_wait("sentinel-stream", b"hello stream")
            finally:
                await producer.delete_stream("sentinel-stream")

    asyncio.run(run())
    return "created stream, published, deleted"


def random_bytes(host: str) -> str:
    """Random unknown bytes on every watched port; the broker will just close the connection."""
    sent = []
    for port in (AMQP_PORT, MQTT_PORT, STREAM_PORT, HTTP_PORT):
        for size in (4, 32):
            payload = os.urandom(size)
            with socket.create_connection((host, port), timeout=5) as s:
                local, remote = s.getsockname(), s.getpeername()
                log(f"random: {size} bytes {payload.hex()} from local port {local[1]} "
                    f"to {remote[0]}:{remote[1]} (host={host}, resolved: {resolve(host, port)})")
                s.sendall(payload)
                time.sleep(0.1)
            sent.append(f"{port}:{payload.hex()}")
    return "sent " + " ".join(sent)


def mismatch(host: str, label: str, port: int, payload: bytes) -> str:
    """Send one protocol's opening bytes to a port that belongs to another protocol.

    The broker does not speak that protocol there, so it answers with its own header or just closes
    the connection; that is expected. The point is that the sentinel sees the wrong protocol.
    """
    with socket.create_connection((host, port), timeout=5) as s:
        local, remote = s.getsockname(), s.getpeername()
        log(f"{label}: {len(payload)} bytes {payload[:16].hex()}... from local port {local[1]} "
            f"to {remote[0]}:{remote[1]} (host={host}, resolved: {resolve(host, port)})")
        s.sendall(payload)
        s.settimeout(1)
        try:
            reply = s.recv(64)
        except (socket.timeout, ConnectionResetError):
            reply = b""
    return f"sent {len(payload)} bytes to port {port}, broker replied {reply[:16]!r}"


def mqtt_on_amqp(host: str) -> str:
    """An MQTT 3.1.1 CONNECT packet sent to the AMQP port."""
    client_id = b"sentinel-mismatch"
    body = (b"\x00\x04MQTT" + b"\x04"          # protocol name and level 4 (3.1.1)
            + b"\x02" + b"\x00\x0a"            # clean session, keepalive 10
            + len(client_id).to_bytes(2, "big") + client_id)
    packet = b"\x10" + bytes([len(body)]) + body
    return mismatch(host, "MQTT -> AMQP port", AMQP_PORT, packet)


def http_on_amqp(host: str) -> str:
    """An HTTP request sent to the AMQP port."""
    request = (f"GET /api/overview HTTP/1.1\r\nHost: {host}:{AMQP_PORT}\r\n"
               "Connection: close\r\n\r\n").encode()
    return mismatch(host, "HTTP -> AMQP port", AMQP_PORT, request)


def stream_on_amqp(host: str) -> str:
    """A RabbitMQ stream PeerProperties frame (the first command of the protocol) sent to the AMQP
    port."""
    def string(text: bytes) -> bytes:
        return len(text).to_bytes(2, "big") + text

    props = string(b"product") + string(b"sentinel")
    body = (b"\x00\x11" + b"\x00\x01"          # key 0x0011 (peer properties), version 1
            + b"\x00\x00\x00\x01"              # correlation id
            + (1).to_bytes(4, "big") + props)  # one property
    frame = len(body).to_bytes(4, "big") + body
    return mismatch(host, "stream -> AMQP port", AMQP_PORT, frame)


TESTS = {
    "amqp091": amqp091,
    "amqp10": amqp10,
    "mqtt": mqtt,
    "http": http,
    "stream": stream,
    "random": random_bytes,
    "mqtt-on-amqp": mqtt_on_amqp,
    "http-on-amqp": http_on_amqp,
    "stream-on-amqp": stream_on_amqp,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("tests", nargs="*", metavar="TEST",
                        help=f"any of: {', '.join(TESTS)} (default: all)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="broker address (default 127.0.0.1; use localhost/::1 to test IPv6)")
    args = parser.parse_args()
    unknown = [t for t in args.tests if t not in TESTS]
    if unknown:
        parser.error(f"unknown test(s) {unknown}; choose from {', '.join(TESTS)}")

    names = args.tests or list(TESTS)
    print(f"protocol-client: host={args.host} tests={','.join(names)} user={USER} "
          f"ports: amqp={AMQP_PORT} mqtt={MQTT_PORT} stream={STREAM_PORT} http={HTTP_PORT}", flush=True)

    failed = 0
    for i, name in enumerate(names):
        if i:
            time.sleep(TEST_PAUSE)  # keeps the tests apart in the sentinel's output
        print(SEPARATOR, flush=True)
        print(f"[ .. ] {name}", flush=True)
        try:
            detail = TESTS[name](args.host)
            print(f"[ OK ] {name:8} {detail}")
        except Exception as e:  # keep going: a failing protocol is still useful traffic
            failed += 1
            print(f"[FAIL] {name:8} {type(e).__name__}: {e}")
    print(SEPARATOR)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
