"""Launch the bundled ZAP daemon when it is not yet reachable.

ZAP ships with the repo under ``tools/`` and is started by ``start-zap.bat``.
Booting it by hand means the Tools page goes back to "not configured" after
every reboot, so WSA starts it in the background instead: a probe first (an
operator-managed or remote ZAP is never shadowed), then the launcher script,
then a poll until the JSON API answers.

Everything here is best effort. A missing bundle, a wrong ``ZAP_API_URL`` or a
failed launch only log - the application never fails because of ZAP.
"""
import logging
import os
import subprocess
import time
from pathlib import Path

from . import zap_service

log = logging.getLogger("wsa.zap")

REPO_ROOT = Path(__file__).resolve().parents[3]
START_BAT = REPO_ROOT / "tools" / "start-zap.bat"
LOCK_FILE = Path(os.getenv("TEMP", "/tmp")) / "wsa-zap-autostart.lock"
# A launch that never became ready would otherwise block the next attempt forever.
LOCK_TTL = 600

DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200


def _locked_recently():
    """True when another process is (or recently was) bringing ZAP up."""
    try:
        age = time.time() - LOCK_FILE.stat().st_mtime
    except OSError:
        return False
    if age < LOCK_TTL:
        return True
    try:
        LOCK_FILE.unlink()
    except OSError:
        pass
    return False


def _mark_started():
    try:
        LOCK_FILE.touch()
    except OSError:
        pass  # the lock is an optimisation, never a hard requirement


def _launch():
    """Start ``tools/start-zap.bat`` detached. Returns True when spawned."""
    if os.name != "nt" or not START_BAT.is_file():
        log.info("ZAP autostart skipped: no launcher at %s", START_BAT)
        return False
    try:
        subprocess.Popen(
            ["cmd", "/c", str(START_BAT)],
            cwd=str(START_BAT.parent),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
        )
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("ZAP autostart failed to start %s: %s", START_BAT, exc)
        return False
    log.info("ZAP autostart: launched %s", START_BAT)
    return True


def ensure_started(config, timeout=None):
    """Make the ZAP API reachable, launching the bundled daemon if needed.

    Returns True once ``core/view/version`` answers. Never raises.
    """
    try:
        if not str(config.get("ZAP_API_URL") or "").strip():
            return False
        ok, _version, _detail = zap_service.ping(config)
        if ok:
            return True
        if _locked_recently() or not _launch():
            return False

        _mark_started()
        deadline = time.time() + (timeout if timeout is not None
                                  else int(config.get("ZAP_AUTOSTART_TIMEOUT") or 180))
        while time.time() < deadline:
            time.sleep(3)
            ok, version, detail = zap_service.ping(config)
            if ok:
                log.info("ZAP autostart: API ready (ZAP %s)", version)
                return True
            if detail and "ConnectionError" not in detail:
                # A refusal from a busy port or a bad key will not self-heal.
                log.warning("ZAP autostart: %s", detail)
        log.warning("ZAP autostart: API not reachable within the timeout.")
    except Exception as exc:  # pragma: no cover - never break app start
        log.warning("ZAP autostart failed: %s", exc)
    return False
