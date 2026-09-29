"""WSA - Web Security Auditing :: application entrypoint."""
import threading, time, webbrowser

from app import create_app, socketio

app = create_app()

if __name__ == "__main__":
    # Open Chrome automatically after a short delay
    def _open_browser():
        time.sleep(1.2)
        try:
            webbrowser.get("chrome").open("http://127.0.0.1:5000")
        except webbrowser.Error:
            webbrowser.open("http://127.0.0.1:5000")
    threading.Thread(target=_open_browser, daemon=True).start()

    socketio.run(app, host="127.0.0.1", port=5000, debug=True, allow_unsafe_werkzeug=True)
