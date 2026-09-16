"""WSA configuration."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _bool(key: str, default: str = "false") -> bool:
    return os.getenv(key, default).strip().lower() in ("1", "true", "yes", "on")


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "wsa-dev-secret-key-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'wsa.db'}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Socket.IO
    SOCKETIO_MESSAGE_QUEUE = None  # use threading mode; no external broker needed
    SOCKETIO_ASYNC_MODE = "threading"

    # Security engines -------------------------------------------------------
    ZAP_API_URL = os.getenv("ZAP_API_URL", "").strip()
    ZAP_API_KEY = os.getenv("ZAP_API_KEY", "").strip()
    ZAP_ENABLED = _bool("ZAP_ENABLED", "true")

    PLAYWRIGHT_ENABLED = _bool("PLAYWRIGHT_ENABLED", "true")
    PLAYWRIGHT_MAX_PAGES = int(os.getenv("PLAYWRIGHT_MAX_PAGES", "12"))
    PLAYWRIGHT_TIMEOUT = int(os.getenv("PLAYWRIGHT_TIMEOUT", "15"))  # seconds

    NUCLEI_BIN = os.getenv("NUCLEI_BIN", "nuclei").strip()
    GOSQLI_BIN = os.getenv("GOSQLI_BIN", "").strip()

    # AI layer ---------------------------------------------------------------
    AI_PROVIDER = os.getenv("AI_PROVIDER", "").strip().lower()
    AI_API_KEY = os.getenv("AI_API_KEY", "").strip()
    AI_MODEL = os.getenv("AI_MODEL", "").strip()
    AI_BASE_URL = os.getenv("AI_BASE_URL", "").strip()

    # Misc -------------------------------------------------------------------
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    REPORTS_DIR = str(BASE_DIR / "reports")
    POLLING_FALLBACK_SECONDS = float(os.getenv("POLLING_FALLBACK_SECONDS", "4"))

    # Background worker
    WORKER_POOL_SIZE = int(os.getenv("WORKER_POOL_SIZE", "3"))
