import socket
from secure_base import SecureChatBase

class SecureChatClient(SecureChatBase):
    def __init__(self, server_ip, port, username, gui_callback):
        super().__init__(username, gui_callback)
        self.server_ip = server_ip
        self.port = port

    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(120)  # 120 second timeout for connection and handshake
            self.socket.connect((self.server_ip, self.port))
            self.gui_callback("Connected to server")

            self._handshake()
            self.socket.settimeout(None)  # Remove timeout for normal chat operations
            self.start_receiving()
        except socket.timeout:
            self.gui_callback("Connection timeout")
        except Exception as e:
            self.gui_callback(f"Connection error: {e}")

    def _handshake(self):
        try:
            self._exchange_certificates(is_server=False)
            self._diffie_hellman(is_server=False)
            self._derive_session_key()
            self.gui_callback("Secure channel established")
        except Exception as e:
            self.gui_callback(f"Handshake error: {e}")
            raise