#!/usr/bin/env python3
"""Dammed Kult online room server.

Players never type an IP address or a port: one player presses CREATE ROOM and gets a
six-character code, the other presses JOIN ROOM and types it. Both game clients connect
*out* to this service over a WebSocket (works behind any home router, on any network),
and the server forwards the game's packets between the two players of a room.

Pure Python standard library (no pip installs). Designed for a free web host:
  * listens on $PORT (Render, Railway, Fly, Koyeb and similar set it), or --port
  * answers plain HTTP GET / and /healthz with 200 for health checks
  * WebSocket endpoint: /ws

    python3 room_server.py --port 8765        # local test
    (on Render: see render.yaml and docs/ONLINE.md)

Protocol (text frames are JSON control messages, binary frames are game data):
  client -> {"op": "create", "v": <protocol version>}
  server -> {"op": "created", "code": "K7Q2MX"}
  client -> {"op": "join", "code": "K7Q2MX", "v": <version>}
  server -> {"op": "paired", "role": "host" | "client"}            (to both players)
  server -> {"op": "error", "reason": "not_found" | "full" | "version" | "busy" | "bad_code"}
  server -> {"op": "peer_left"}
  binary frames from a paired player are forwarded unchanged to the other player.

Safety: game data is never parsed; control messages are size-limited JSON; codes are
validated against a fixed alphabet; per-connection rate limits; idle rooms expire; no
files are read or written and nothing received is executed.
"""
import argparse
import asyncio
import base64
import hashlib
import json
import os
import secrets
import struct
import time

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"   # no 0/O, 1/I/L: nothing ambiguous to read out
CODE_LEN = 6
MAX_ROOMS = 1000
MAX_MESSAGE = 4096
MAX_HEADER = 8192
RATE_PER_SECOND = 400
ROOM_WAIT_SECONDS = 30 * 60
IDLE_SECONDS = 90
PING_SECONDS = 20
PROTOCOL_VERSIONS = {4}

rooms = {}          # code -> Room
stats = {"connections": 0, "rooms_created": 0, "started": time.time()}


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


class Room:
    def __init__(self, code, host, version):
        self.code = code
        self.host = host
        self.guest = None
        self.version = version
        self.created = time.time()


class Conn:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.room = None
        self.role = ""
        self.closed = False
        self.last_seen = time.time()
        self.win_start = time.time()
        self.win_count = 0
        self.lock = asyncio.Lock()

    def peer(self):
        r = self.room
        if r is None:
            return None
        return r.guest if self is r.host else r.host

    async def send_frame(self, opcode, payload: bytes):
        if self.closed:
            return
        n = len(payload)
        head = bytes([0x80 | opcode])
        if n < 126:
            head += bytes([n])
        elif n < 65536:
            head += bytes([126]) + struct.pack("!H", n)
        else:
            head += bytes([127]) + struct.pack("!Q", n)
        try:
            async with self.lock:
                self.writer.write(head + payload)
                await self.writer.drain()
        except (ConnectionError, RuntimeError):
            self.closed = True

    async def send_json(self, obj):
        await self.send_frame(0x1, json.dumps(obj, separators=(",", ":")).encode())

    async def read_frame(self):
        """Returns (opcode, payload) or None when the connection ends or misbehaves."""
        hdr = await self.reader.readexactly(2)
        fin = hdr[0] & 0x80
        opcode = hdr[0] & 0x0F
        masked = hdr[1] & 0x80
        n = hdr[1] & 0x7F
        if n == 126:
            n = struct.unpack("!H", await self.reader.readexactly(2))[0]
        elif n == 127:
            n = struct.unpack("!Q", await self.reader.readexactly(8))[0]
        if not masked or n > MAX_MESSAGE:
            return None
        mask = await self.reader.readexactly(4)
        data = bytearray(await self.reader.readexactly(n))
        for i in range(n):
            data[i] ^= mask[i & 3]
        if not fin and opcode in (0x1, 0x2):
            # Fragmented messages are not used by the game; collect up to the limit.
            while True:
                op2, more = await self.read_frame_raw()
                data += more
                if len(data) > MAX_MESSAGE:
                    return None
                if op2 & 0x80:
                    break
        return opcode, bytes(data)

    async def read_frame_raw(self):
        hdr = await self.reader.readexactly(2)
        n = hdr[1] & 0x7F
        if n == 126:
            n = struct.unpack("!H", await self.reader.readexactly(2))[0]
        elif n == 127:
            n = struct.unpack("!Q", await self.reader.readexactly(8))[0]
        if n > MAX_MESSAGE:
            raise ConnectionError("too large")
        mask = await self.reader.readexactly(4)
        data = bytearray(await self.reader.readexactly(n))
        for i in range(n):
            data[i] ^= mask[i & 3]
        return hdr[0], bytes(data)

    def rate_ok(self):
        now = time.time()
        if now - self.win_start >= 1.0:
            self.win_start = now
            self.win_count = 0
        self.win_count += 1
        return self.win_count <= RATE_PER_SECOND


def new_code():
    for _ in range(50):
        code = "".join(secrets.choice(ALPHABET) for _ in range(CODE_LEN))
        if code not in rooms:
            return code
    return None


def clean_code(s):
    if not isinstance(s, str):
        return None
    s = s.strip().upper().replace(" ", "").replace("-", "")
    if len(s) != CODE_LEN or any(c not in ALPHABET for c in s):
        return None
    return s


async def leave_room(c: Conn):
    r = c.room
    if r is None:
        return
    other = c.peer()
    if c is r.host:
        rooms.pop(r.code, None)
        if other is not None:
            other.room = None
            await other.send_json({"op": "peer_left"})
        log("room", r.code, "closed (host left)")
    else:
        r.guest = None
        if other is not None:
            await other.send_json({"op": "peer_left"})
        log("room", r.code, "guest left; room open again")
    c.room = None


async def on_control(c: Conn, msg: dict):
    op = msg.get("op")
    version = msg.get("v")
    if op == "create":
        if c.room is not None:
            await leave_room(c)
        if version not in PROTOCOL_VERSIONS:
            await c.send_json({"op": "error", "reason": "version"})
            return
        if len(rooms) >= MAX_ROOMS:
            await c.send_json({"op": "error", "reason": "busy"})
            return
        code = new_code()
        if code is None:
            await c.send_json({"op": "error", "reason": "busy"})
            return
        rooms[code] = Room(code, c, version)
        c.room = rooms[code]
        c.role = "host"
        stats["rooms_created"] += 1
        await c.send_json({"op": "created", "code": code})
        log("room", code, "created")
    elif op == "join":
        code = clean_code(msg.get("code"))
        if code is None:
            await c.send_json({"op": "error", "reason": "bad_code"})
            return
        r = rooms.get(code)
        if r is None:
            await c.send_json({"op": "error", "reason": "not_found"})
            return
        if r.guest is not None or r.host is c:
            await c.send_json({"op": "error", "reason": "full"})
            return
        if version != r.version:
            await c.send_json({"op": "error", "reason": "version"})
            return
        if c.room is not None:
            await leave_room(c)
        r.guest = c
        c.room = r
        c.role = "client"
        await r.host.send_json({"op": "paired", "role": "host"})
        await c.send_json({"op": "paired", "role": "client"})
        log("room", code, "paired")
    elif op == "leave":
        await leave_room(c)
    elif op == "ping":
        await c.send_json({"op": "pong"})


async def ws_session(c: Conn):
    stats["connections"] += 1
    try:
        while not c.closed:
            try:
                fr = await asyncio.wait_for(c.read_frame(), timeout=IDLE_SECONDS)
            except asyncio.TimeoutError:
                break
            if fr is None:
                break
            c.last_seen = time.time()
            opcode, data = fr
            if not c.rate_ok():
                continue
            if opcode == 0x8:
                await c.send_frame(0x8, data[:2])
                break
            if opcode == 0x9:
                await c.send_frame(0xA, data)
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x1:
                try:
                    msg = json.loads(data.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
                if isinstance(msg, dict):
                    await on_control(c, msg)
            elif opcode == 0x2:
                other = c.peer()
                if other is not None and not other.closed:
                    await other.send_frame(0x2, data)
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    finally:
        c.closed = True
        await leave_room(c)
        try:
            c.writer.close()
        except Exception:
            pass


async def handle(reader, writer):
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
        writer.close()
        return
    if len(raw) > MAX_HEADER:
        writer.close()
        return
    lines = raw.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) > 1 else "/"
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    if path.split("?")[0] == "/ws" and headers.get("upgrade", "").lower() == "websocket" and "sec-websocket-key" in headers:
        accept = base64.b64encode(hashlib.sha1((headers["sec-websocket-key"] + GUID).encode()).digest()).decode()
        writer.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      "Sec-WebSocket-Accept: %s\r\n\r\n" % accept).encode())
        await writer.drain()
        await ws_session(Conn(reader, writer))
        return
    body = ("Dammed Kult room server: ok. rooms=%d\n" % len(rooms)).encode()
    status = "200 OK" if method in ("GET", "HEAD") else "405 Method Not Allowed"
    writer.write(("HTTP/1.1 %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (status, len(body))).encode()
                 + (body if method == "GET" else b""))
    try:
        await writer.drain()
    except ConnectionError:
        pass
    writer.close()


async def janitor():
    while True:
        await asyncio.sleep(PING_SECONDS)
        now = time.time()
        for code, r in list(rooms.items()):
            if r.guest is None and now - r.created > ROOM_WAIT_SECONDS:
                rooms.pop(code, None)
                await r.host.send_json({"op": "error", "reason": "expired"})
                r.host.room = None
                log("room", code, "expired")
        # keep-alive pings so hosting proxies do not drop quiet connections
        seen = set()
        for r in list(rooms.values()):
            for c in (r.host, r.guest):
                if c is not None and id(c) not in seen:
                    seen.add(id(c))
                    await c.send_frame(0x9, b"ka")


async def main():
    ap = argparse.ArgumentParser(description="Dammed Kult online room server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8765")))
    args = ap.parse_args()
    server = await asyncio.start_server(handle, args.host, args.port, limit=MAX_HEADER)
    log("Dammed Kult room server on %s:%d  (WebSocket path /ws)" % (args.host, args.port))
    asyncio.create_task(janitor())
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
