import socket
import threading
from secure_base import SecureChatBase

class SecureChatServer(SecureChatBase):
    def __init__(self, port, username, gui_callback):
        super().__init__(username, gui_callback)
        self.port = port

    def start(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(60)  # 60 second timeout for accept
            s.bind(("0.0.0.0", self.port))
            s.listen(1)
            self.gui_callback(f"Server listening on port {self.port}")

            self.socket, addr = s.accept()
            self.socket.settimeout(120)  # 120 second timeout for handshake operations
            self.gui_callback(f"Client connected from {addr[0]}:{addr[1]}")

            self._handshake()
            self.socket.settimeout(None)  # Remove timeout for normal chat operations
            self.start_receiving()
        except socket.timeout:
            self.gui_callback("Connection timeout")
        except Exception as e:
            self.gui_callback(f"Server error: {e}")

    def _handshake(self):
        try:
            self._exchange_certificates(is_server=True)
            self._diffie_hellman(is_server=True)
            self._derive_session_key()
            self.gui_callback("Secure channel established")
        except Exception as e:
            self.gui_callback(f"Handshake error: {e}")
            raise