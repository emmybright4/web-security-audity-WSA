"""Mail diagnostics: where do WSA verification codes actually go?

    python _mail_check.py                  # delivery mode + the newest message/code
    python _mail_check.py you@gmail.com    # send a real test message, report the result

With ``MAIL_FILE_DELIVERY=true`` and no ``MAIL_SERVER``, WSA does not send mail at
all: it writes each message to ``instance/mail/<timestamp>.eml``. This script
prints the newest code from there so a local sign-in can be finished without an
inbox, and it exercises the real delivery path when an address is given.

Development tool: it prints live codes by design. Do not point it at production.
"""
import email
import os
import re
import sys

FALLBACK_DIR = os.path.join("instance", "mail")


def newest_messages(directory, limit=5):
    try:
        names = [n for n in os.listdir(directory) if n.endswith(".eml")]
    except OSError:
        return []
    paths = [os.path.join(directory, n) for n in names]
    paths.sort(key=os.path.getmtime, reverse=True)
    return paths[:limit]


def code_in(path):
    """The newest code cell rendered by ``email_service.code_block``."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        # undo quoted-printable soft line breaks first
        raw = handle.read().replace("=\r\n", "").replace("=\n", "")
    digits = re.findall(r"min-width:38px[^>]*>(\d)</span>", raw)
    return "".join(digits[:6]) if len(digits) >= 6 else None


def read_message(path):
    with open(path, encoding="utf-8", errors="replace") as handle:
        return email.message_from_string(handle.read())


def main():
    from app import create_app
    from app.services import email_service

    recipient = (sys.argv[1] if len(sys.argv) > 1 else "").strip()
    app = create_app()
    with app.app_context():
        server = (app.config.get("MAIL_SERVER") or "").strip()
        file_mode = bool(app.config.get("MAIL_FILE_DELIVERY"))
        directory = os.path.abspath(app.config.get("MAIL_FILE_DIR") or FALLBACK_DIR)
        print("delivery mode :", f"SMTP via {server}:{app.config.get('MAIL_PORT')}" if server
              else ("file delivery - messages are NOT emailed" if file_mode
                    else "not configured - nothing can be delivered"))
        print("sender        :", app.config.get("MAIL_SENDER") or "(not set)")
        print("dev mailbox   :", directory)

        if recipient:
            html = email_service.layout(
                "WSA - mail delivery test",
                "<p>If you can read this, WSA can deliver verification codes.</p>")
            row = email_service.send_email(recipient, "WSA - mail delivery test", html,
                                           email_type="delivery_test")
            print("result        :", row.status, str(row.error_message or "").strip())
            print("where         :", row.provider_message_id or "(none)")
            if row.status != "sent":
                print("\ncheck, in this order:")
                print("  * MAIL_SERVER / MAIL_PORT / MAIL_USE_TLS match the provider")
                print("  * MAIL_USERNAME is the full address; MAIL_PASSWORD an app password")
                print("    (Gmail: 2-Step Verification on, then create an App Password)")
                print("  * MAIL_SENDER usually has to equal MAIL_USERNAME")
                return 1
            print(f"delivered - check {recipient} in a moment")
            return 0

        messages = newest_messages(directory)
        if not messages:
            print("\nno messages yet - register or sign in once, then run this again")
            return 0
        print("\nnewest messages (codes shown because this is the development mailbox):")
        for index, path in enumerate(messages):
            msg = read_message(path)
            code = code_in(path)
            suffix = f"   <- newest code: {code}" if index == 0 and code else ""
            print(f"  {os.path.basename(path)}  to={msg['To']}  {msg['Subject']}{suffix}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
