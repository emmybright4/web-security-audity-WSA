"""Probe the login page's computed layout via CDP to find why it renders blank."""
import json
import time
import urllib.request

DEBUG = "http://127.0.0.1:9222"

import importlib.util, sys, os
# reuse minimal CDP helpers inline (ws client deleted earlier)
import socket, struct, base64, os as _os, urllib.parse


def new_tab(url):
    req = urllib.request.Request(
        DEBUG + "/json/new?" + urllib.parse.urlencode({"url": url}), method="PUT")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)["webSocketDebuggerUrl"]


def ws_connect(ws_url):
    p = urllib.parse.urlparse(ws_url)
    sock = socket.create_connection((p.hostname, p.port), timeout=10)
    key = base64.b64encode(_os.urandom(16)).decode()
    path = p.path + (("?" + p.query) if p.query else "")
    req = (f"GET {path} HTTP/1.1\r\nHost: {p.hostname}:{p.port}\r\n"
           "Upgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
    sock.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += sock.recv(4096)
    assert b"101" in buf.split(b"\r\n", 1)[0]
    return sock


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def ws_recv(sock):
    b1, b2 = _recv_exact(sock, 2)
    opcode = b1 & 0x0F
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack(">H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", _recv_exact(sock, 8))[0]
    payload = _recv_exact(sock, length)
    if opcode == 9:
        ws_send(sock, b"")
        return ws_recv(sock)
    if opcode == 8:
        raise ConnectionError("closed")
    return json.loads(payload.decode("utf-8", "replace"))


def ws_send(sock, obj):
    payload = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    head = bytearray([0x81])
    n = len(payload)
    if n < 126:
        head.append(0x80 | n)
    elif n < 65536:
        head.append(0x80 | 126)
        head += struct.pack(">H", n)
    else:
        head.append(0x80 | 127)
        head += struct.pack(">Q", n)
    mask = _os.urandom(4)
    head += mask
    sock.sendall(bytes(head) + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


_ids = iter(range(1, 10000))


def evaluate(sock, expr, timeout=10):
    ws_send(sock, {"id": next(_ids), "method": "Runtime.evaluate",
                   "params": {"expression": expr, "returnByValue": True,
                              "awaitPromise": True}})
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            sock.settimeout(max(0.1, deadline - time.time()))
            msg = ws_recv(sock)
        except Exception:
            return None
        if "id" in msg:
            return msg.get("result", {}).get("result", {}).get("value")
    return None


sock = ws_connect(new_tab("about:blank"))
for m in ("Runtime.enable", "Page.enable"):
    ws_send(sock, {"id": 1, "method": m})
ws_send(sock, {"id": 2, "method": "Page.navigate",
               "params": {"url": "http://127.0.0.1:5000/login?next=%2F"}})
time.sleep(5)

expr = """JSON.stringify({
  authShellCount: document.querySelectorAll('.auth-shell').length,
  shellCount: document.querySelectorAll('.wsa-shell').length,
  authShellDisplay: getComputedStyle(document.querySelector('.auth-shell') || document.body).display,
  authShellRect: (document.querySelector('.auth-shell') || {}).getBoundingClientRect ? JSON.stringify(document.querySelector('.auth-shell').getBoundingClientRect()) : 'n/a',
  authBrandDisplay: (() => { const e = document.querySelector('.auth-brand'); return e ? getComputedStyle(e).display + ' w=' + e.getBoundingClientRect().width : 'MISSING'; })(),
  authPanelDisplay: (() => { const e = document.querySelector('.auth-panel'); return e ? getComputedStyle(e).display + ' w=' + e.getBoundingClientRect().width : 'MISSING'; })(),
  loginFormVisible: (() => { const e = document.getElementById('loginForm'); if (!e) return 'MISSING'; const r = e.getBoundingClientRect(); return r.width + 'x' + r.height + ' at ' + r.top; })(),
  elemAtCenter: (() => { const e = document.elementFromPoint(innerWidth/2, innerHeight/2); return e ? e.tagName + '.' + e.className : 'none'; })(),
  bodyChildren: Array.from(document.body.children).map(e => e.tagName + (e.id ? '#' + e.id : '') + (e.className ? '.' + String(e.className).split(' ')[0] : '') + ' dh=' + getComputedStyle(e).display),
  bodyBg: getComputedStyle(document.body).backgroundColor,
  htmlOverflow: getComputedStyle(document.documentElement).overflow + '/' + getComputedStyle(document.body).overflow,
  viewportScroll: JSON.stringify({x: scrollX, y: scrollY, ih: innerHeight, sh: document.documentElement.scrollHeight}),
})"""
print(evaluate(sock, expr))
sock.close()
