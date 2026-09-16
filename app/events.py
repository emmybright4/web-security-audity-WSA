"""Socket.IO event handlers."""
import logging

log = logging.getLogger("wsa.events")


def register_socketio_events(socketio):
    @socketio.on("connect")
    def on_connect():
        log.info("Socket.IO client connected")

    @socketio.on("disconnect")
    def on_disconnect():
        log.info("Socket.IO client disconnected")
