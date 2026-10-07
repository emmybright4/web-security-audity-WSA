"""Socket.IO event handlers."""
import logging

from flask_login import current_user
from flask_socketio import join_room

log = logging.getLogger("wsa.events")


def register_socketio_events(socketio):
    @socketio.on("connect")
    def on_connect():
        # Every signed-in socket joins a private room. Scan workers emit to
        # "user:<id>", so one account's findings never reach another's browser.
        try:
            row = getattr(current_user, "row", None)
        except Exception:
            row = None
        if row is not None:
            join_room(f"user:{row.id}")
            log.info("Socket.IO client connected (user %s)", row.id)
        else:
            log.info("Socket.IO client connected (anonymous)")

    @socketio.on("disconnect")
    def on_disconnect():
        log.info("Socket.IO client disconnected")
