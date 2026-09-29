"""Rate limiting for untrusted endpoints (OTP send/verify, login, reset).

A small in-process sliding window keyed by ``(scope, identity)``. It needs no
external service and is deliberately conservative: a per-deployment limit is
fine for a self-hosted WSA instance, and a distributed store can be swapped in
behind :func:`check` later.
"""
import threading
import time
from collections import defaultdict, deque

_lock = threading.Lock()
_hits = defaultdict(deque)
# Bound memory: drop windows that are already idle.
_LAST_GC = {"at": 0.0}


def check(scope, identity, limit, window):
    """Consume one unit of quota.

    Returns ``(allowed, retry_after_seconds)``. ``retry_after`` is 0 when the
    request is allowed.
    """
    limit = max(1, int(limit or 1))
    window = max(1, int(window or 1))
    key = (scope, str(identity or "anonymous"))
    now = time.time()
    cutoff = now - window

    with _lock:
        _gc(now)
        bucket = _hits[key]
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= limit:
            return False, max(1, int(bucket[0] + window - now) + 1)
        bucket.append(now)
        return True, 0


def peek(scope, identity, limit, window):
    """Remaining quota without consuming any."""
    key = (scope, str(identity or "anonymous"))
    cutoff = time.time() - max(1, int(window or 1))
    with _lock:
        bucket = _hits.get(key)
        used = len([t for t in bucket if t > cutoff]) if bucket else 0
    return max(0, max(1, int(limit or 1)) - used)


def reset(scope=None, identity=None):
    with _lock:
        if scope is None:
            _hits.clear()
            return
        if identity is None:
            for key in [k for k in _hits if k[0] == scope]:
                _hits.pop(key, None)
            return
        _hits.pop((scope, str(identity)), None)


def _gc(now):
    if now - _LAST_GC["at"] < 60:
        return
    _LAST_GC["at"] = now
    stale = [key for key, bucket in _hits.items() if not bucket or bucket[-1] < now - 3600]
    for key in stale:
        _hits.pop(key, None)
