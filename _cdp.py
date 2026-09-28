"""Minimal Chrome DevTools Protocol client for end-to-end browser checks.

Scratch tooling: drives the real app in real Chrome, records console errors,
page exceptions and failed network requests, and evaluates JS in the page.
"""
import base64
import json
import os
import socket
import struct
import time
import urllib.parse
import urllib.request

DEBUG = "http://127.0.0.1:9222"


# ----------------------------------------------------------------- targets --
def new_tab(url="about:blank"):
    req = urllib.request.Request(
        DEBUG + "/json/new?" + urllib.parse.urlencode({"url": url}), method="PUT")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def close_tab(tab_id):
    try:
        req = urllib.request.Request(DEBUG + "/json/close/" + tab_id, method="GET")
        urllib.request.urlopen(req, timeout=5).read()
    except Exception:
        pass


# ------------------------------------------------------------- ws framing --
def _ws_connect(ws_url):
    p = urllib.parse.urlparse(ws_url)
    sock = socket.create_connection((p.hostname, p.port), timeout=15)
    key = base64.b64encode(os.urandom(16)).decode()
    path = p.path + (("?" + p.query) if p.query else "")
    sock.sendall(
        f"GET {path} HTTP/1.1\r\nHost: {p.hostname}:{p.port}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("handshake closed")
        buf += chunk
    if b" 101 " not in buf.split(b"\r\n", 1)[0]:
        raise ConnectionError("handshake failed: " + buf.split(b"\r\n", 1)[0].decode())
    return sock


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("socket closed")
        data += chunk
    return data


def _ws_send_frame(sock, opcode, payload):
    head = bytearray([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head.append(0x80 | n)
    elif n < 65536:
        head.append(0x80 | 126)
        head += struct.pack(">H", n)
    else:
        head.append(0x80 | 127)
        head += struct.pack(">Q", n)
    mask = os.urandom(4)
    head += mask
    sock.sendall(bytes(head) + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


def _ws_recv_frame(sock):
    b1, b2 = _recv_exact(sock, 2)
    opcode = b1 & 0x0F
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack(">H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", _recv_exact(sock, 8))[0]
    payload = _recv_exact(sock, length)
    return opcode, payload


class Page:
    """A CDP session bound to one browser tab."""

    def __init__(self, url="about:blank", width=1440, height=900):
        tab = new_tab("about:blank")
        self.tab_id = tab["id"]
        self.sock = _ws_connect(tab["webSocketDebuggerUrl"])
        self._id = 0
        self.console = []          # (level, text)
        self.exceptions = []       # exception descriptions
        self.failed_requests = []  # (url, errorText / status)
        self.responses = []        # (status, url)
        self.events = []           # all event method names seen
        self.send("Runtime.enable")
        self.send("Log.enable")
        self.send("Page.enable")
        self.send("Network.enable")
        self.send("Emulation.setDeviceMetricsOverride",
                  {"width": width, "height": height, "deviceScaleFactor": 1,
                   "mobile": False})
        if url != "about:blank":
            self.goto(url)

    # ------------------------------------------------------------- plumbing --
    def send(self, method, params=None, timeout=20):
        self._id += 1
        want = self._id
        _ws_send_frame(self.sock, 0x1,
                       json.dumps({"id": want, "method": method,
                                   "params": params or {}}).encode())
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.sock.settimeout(max(0.05, deadline - time.time()))
            try:
                opcode, payload = _ws_recv_frame(self.sock)
            except socket.timeout:
                continue
            if opcode == 0x8:
                raise ConnectionError("page socket closed")
            if opcode == 0x9:
                _ws_send_frame(self.sock, 0xA, payload)
                continue
            if opcode not in (0x1, 0x2):
                continue
            try:
                msg = json.loads(payload)
            except ValueError:
                continue
            if "method" in msg:
                self._record(msg)
                continue
            if msg.get("id") == want:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})
        raise TimeoutError(f"no reply for {method}")

    def _record(self, msg):
        method = msg["method"]
        p = msg.get("params", {})
        self.events.append(method)
        if method == "Runtime.consoleAPICalled":
            level = p.get("type", "log")
            text = " ".join(str(a.get("value", a.get("description", "")))
                            for a in p.get("args", []))
            self.console.append((level, text))
        elif method == "Log.entryAdded":
            e = p.get("entry", {})
            self.console.append((e.get("level", "log"), e.get("text", "")))
        elif method == "Runtime.exceptionThrown":
            d = p.get("exceptionDetails", {})
            desc = (d.get("exception") or {}).get("description") or d.get("text", "")
            self.exceptions.append(desc)
        elif method == "Network.loadingFailed":
            self.failed_requests.append((p.get("requestId"), p.get("errorText")))
        elif method == "Network.responseReceived":
            r = p.get("response", {})
            self.responses.append((r.get("status"), r.get("url")))

    def drain(self, seconds=1.0):
        """Keep pulling events for a while so nothing is missed."""
        deadline = time.time() + seconds
        while time.time() < deadline:
            self.sock.settimeout(max(0.05, deadline - time.time()))
            try:
                opcode, payload = _ws_recv_frame(self.sock)
            except socket.timeout:
                continue
            except Exception:
                return
            if opcode == 0x9:
                _ws_send_frame(self.sock, 0xA, payload)
                continue
            if opcode != 0x1:
                continue
            try:
                msg = json.loads(payload)
            except ValueError:
                continue
            if "method" in msg:
                self._record(msg)

    # ----------------------------------------------------------------- api --
    def goto(self, url, settle=2.5):
        self.send("Page.navigate", {"url": url})
        self.drain(settle)
        return self

    def eval(self, expr, timeout=20):
        r = self.send("Runtime.evaluate",
                      {"expression": expr, "returnByValue": True,
                       "awaitPromise": True}, timeout=timeout)
        res = r.get("result", {})
        if r.get("exceptionDetails"):
            details = r["exceptionDetails"]
            desc = ((details.get("exception") or {}).get("description")
                    or details.get("text") or "eval failed")
            raise RuntimeError(desc)
        return res.get("value")

    def console_errors(self):
        out = [f"{lvl}: {txt}" for lvl, txt in self.console
               if lvl in ("error", "assert", "warning")]
        out += [f"exception: {e}" for e in self.exceptions]
        out += [f"http {s} {u}" for s, u in self.responses if s and s >= 400]
        out += [f"network-fail {rid}: {err}" for rid, err in self.failed_requests]
        return out

    def close(self):
        try:
            self.sock.close()
        finally:
            close_tab(self.tab_id)
