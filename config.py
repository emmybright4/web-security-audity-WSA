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
    # Optional MCP endpoint for the ZAP-MCP card. When empty the card falls back
    # to native ZAP API mode (see services/engines/zap_mcp.py).
    ZAP_MCP_URL = os.getenv("ZAP_MCP_URL", "").strip()
    # Launch tools/start-zap.bat in the background when ZAP is not yet reachable,
    # so the Tools page keeps a live status after a reboot.
    ZAP_AUTOSTART = _bool("ZAP_AUTOSTART", "true")
    ZAP_AUTOSTART_TIMEOUT = int(os.getenv("ZAP_AUTOSTART_TIMEOUT", "180"))

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

    # ---------------------------------------------------------------------
    # One-time passwords (email / SMS verification, password reset, MFA)
    # ---------------------------------------------------------------------
    OTP_LENGTH = int(os.getenv("OTP_LENGTH", "6"))
    OTP_EXPIRATION_MINUTES = int(os.getenv("OTP_EXPIRATION_MINUTES", "10"))
    OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "5"))
    OTP_RESEND_COOLDOWN_SECONDS = int(os.getenv("OTP_RESEND_COOLDOWN_SECONDS", "60"))
    # ---------------------------------------------------------------------
    # Email verification policy
    # ---------------------------------------------------------------------
    # Master switch. false = this instance does not verify email addresses at all:
    # sign-up creates a usable account immediately (no code email, no mail server
    # required) and sign-in asks for nothing but the password. true = the shipped
    # default: sign-up proves the address with a code before the account can be
    # used, and LOGIN_OTP_ENABLED then decides whether every *sign-in* also needs
    # a code.
    EMAIL_VERIFICATION_ENABLED = _bool("EMAIL_VERIFICATION_ENABLED", "true")

    # Sign-in verification: after a correct password a one-time code is emailed
    # to the account's verified address, and only that code promotes the session
    # to a real login. Only consulted while EMAIL_VERIFICATION_ENABLED is true.
    # Requires working email delivery: MAIL_SERVER, or MAIL_FILE_DELIVERY=true.
    LOGIN_OTP_ENABLED = _bool("LOGIN_OTP_ENABLED", "true")

    # ---------------------------------------------------------------------
    # Email (SMTP) delivery
    # ---------------------------------------------------------------------
    MAIL_SERVER = os.getenv("MAIL_SERVER", "").strip()
    MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "").strip()
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "").strip()
    MAIL_USE_TLS = _bool("MAIL_USE_TLS", "true")
    MAIL_USE_SSL = _bool("MAIL_USE_SSL", "false")
    MAIL_SENDER = os.getenv("MAIL_SENDER", "").strip() or os.getenv("MAIL_USERNAME", "").strip()
    MAIL_SENDER_NAME = os.getenv("MAIL_SENDER_NAME", "WSA - Web Security Auditing").strip()
    MAIL_TIMEOUT_SECONDS = int(os.getenv("MAIL_TIMEOUT_SECONDS", "20"))
    # When SMTP is not configured the API must say so instead of pretending to
    # have delivered a code. Set to "true" to allow writes to a local file
    # instead of SMTP (development only).
    MAIL_FILE_DELIVERY = _bool("MAIL_FILE_DELIVERY", "false")
    MAIL_FILE_DIR = os.getenv("MAIL_FILE_DIR", str(BASE_DIR / "instance" / "mail")).strip()

    # ---------------------------------------------------------------------
    # SMS delivery (provider chosen purely by environment configuration)
    # ---------------------------------------------------------------------
    SMS_PROVIDER = os.getenv("SMS_PROVIDER", "").strip().lower()
    SMS_API_KEY = os.getenv("SMS_API_KEY", "").strip()
    SMS_API_SECRET = os.getenv("SMS_API_SECRET", "").strip()
    SMS_SENDER_ID = os.getenv("SMS_SENDER_ID", "").strip()
    SMS_API_URL = os.getenv("SMS_API_URL", "").strip()
    SMS_TIMEOUT_SECONDS = int(os.getenv("SMS_TIMEOUT_SECONDS", "20"))
    # "console" writes messages to the SMS outbox log below instead of a
    # gateway. Never enable in production: it stores message bodies in a file.
    SMS_ALLOW_FILE_PROVIDER = _bool("SMS_ALLOW_FILE_PROVIDER", "false")
    SMS_FILE_DIR = os.getenv("SMS_FILE_DIR", str(BASE_DIR / "instance" / "sms")).strip()

    # ---------------------------------------------------------------------
    # Rate limiting (in-process sliding window; per deployment)
    # ---------------------------------------------------------------------
    # Registration is separate from OTP sending: it is a much rarer event, and
    # a shared limit made a self-hosted instance (where every request comes from
    # one IP) lock out its own operator after five sign-ups.
    RATE_LIMIT_REGISTER = (int(os.getenv("RATE_LIMIT_REGISTER", "30")),
                           int(os.getenv("RATE_LIMIT_REGISTER_WINDOW", "3600")))
    RATE_LIMIT_OTP_SEND = (int(os.getenv("RATE_LIMIT_OTP_SEND", "5")),
                           int(os.getenv("RATE_LIMIT_OTP_SEND_WINDOW", "3600")))
    RATE_LIMIT_OTP_VERIFY = (int(os.getenv("RATE_LIMIT_OTP_VERIFY", "10")),
                             int(os.getenv("RATE_LIMIT_OTP_VERIFY_WINDOW", "600")))
    RATE_LIMIT_LOGIN = (int(os.getenv("RATE_LIMIT_LOGIN", "10")),
                        int(os.getenv("RATE_LIMIT_LOGIN_WINDOW", "600")))
    RATE_LIMIT_PASSWORD_RESET = (int(os.getenv("RATE_LIMIT_PASSWORD_RESET", "5")),
                                 int(os.getenv("RATE_LIMIT_PASSWORD_RESET_WINDOW", "3600")))

    # Notifications ---------------------------------------------------------
    NOTIFICATIONS_ENABLED = _bool("NOTIFICATIONS_ENABLED", "true")

    # Misc -------------------------------------------------------------------
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    REPORTS_DIR = str(BASE_DIR / "reports")
    POLLING_FALLBACK_SECONDS = float(os.getenv("POLLING_FALLBACK_SECONDS", "4"))

    # Background worker
    WORKER_POOL_SIZE = int(os.getenv("WORKER_POOL_SIZE", "3"))
