import socket
import threading
import json
import os
import time
from datetime import datetime, timezone, timedelta
from queue import Queue

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac


class SecureChatBase:
    def __init__(self, username, gui_callback):
        self.username = username
        self.gui_callback = gui_callback

        self.socket = None
        self.running = False

        self.sequence = 0
        self.peer_sequence = -1

        self.msg_queue = Queue()
        self.sign_messages = True

        self.session_key = None
        self.hmac_key = None
        self.peer_username = None

        self.log_file = os.path.join(os.getcwd(), f"{username}_chat.log")
        self.history_dir = os.path.join(os.getcwd(), "chat_history")

        self._ensure_history_dir()
        self._setup_crypto()

        self.history_cache = None
        self.history_loaded = False
        self._write_lock = threading.Lock()
        self._batch_history = []
        self._last_history_write = time.time()

    def _ensure_history_dir(self):
        if not os.path.exists(self.history_dir):
            os.makedirs(self.history_dir)

    def _get_history_filename(self):
        if not self.peer_username:
            return None
        users = sorted([self.username, self.peer_username])
        filename = f"{users[0]}_{users[1]}_history.json"
        return os.path.join(self.history_dir, filename)

    def _save_message_to_history(self, sender, message, timestamp):
        if not self.peer_username:
            return
        self._batch_history.append({
            "sender": sender,
            "message": message,
            "timestamp": timestamp
        })
        current_time = time.time()
        if len(self._batch_history) >= 10 or (current_time - self._last_history_write) >= 5:
            self._flush_history_batch()

    def _flush_history_batch(self):
        if not self._batch_history:
            return
        with self._write_lock:
            history_file = self._get_history_filename()
            if self.history_cache is not None:
                history = self.history_cache
            else:
                history = []
                if os.path.exists(history_file):
                    try:
                        with open(history_file, "r", encoding="utf-8") as f:
                            history = json.load(f)
                    except:
                        history = []
            history.extend(self._batch_history)
            self.history_cache = history
            try:
                with open(history_file, "w", encoding="utf-8") as f:
                    json.dump(history, f, indent=2, ensure_ascii=False)
                self._batch_history.clear()
                self._last_history_write = time.time()
            except Exception as e:
                print(f"Error saving history: {e}")

    def _load_chat_history(self):
        if not self.peer_username or self.history_loaded:
            return
        self.history_loaded = True
        history_file = self._get_history_filename()
        if not os.path.exists(history_file):
            return
        try:
            with open(history_file, "r", encoding="utf-8") as f:
                history = json.load(f)
            self.history_cache = history
            if not history:
                return
            self.gui_callback("═" * 50)
            self.gui_callback("📜 Loading previous chat history...")
            self.gui_callback("═" * 50)
            display_history = history[-50:] if len(history) > 50 else history
            if len(history) > 50:
                self.gui_callback(f"... ({len(history) - 50} older messages not shown)")
            for msg in display_history:
                sender = msg.get("sender", "Unknown")
                message = msg.get("message", "")
                timestamp = msg.get("timestamp", "")
                try:
                    dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    time_str = dt.strftime("%Y-%m-%d %H:%M")
                except:
                    time_str = timestamp
                if sender == self.username:
                    self.gui_callback(f"[{time_str}] You: {message}")
                else:
                    self.gui_callback(f"[{time_str}] {sender}: {message}")
            self.gui_callback("═" * 50)
            self.gui_callback("📍 Current session starts below")
            self.gui_callback("═" * 50)
        except Exception as e:
            print(f"Error loading history: {e}")

    def _setup_crypto(self):
        print(f"[DEBUG] {self.username}: Generating RSA-4096 key pair...")
        # Enhanced RSA key size (4096 bits for better security)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "EG"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AAST"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.username),
        ])
        
        # Enhanced certificate with SHA-256
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(self.private_key, hashes.SHA256(), default_backend())
        )
        print(f"[DEBUG] {self.username}: Crypto setup complete")

    def _recv_exact(self, n):
        """Receive exactly n bytes - with better error handling"""
        data = b""
        remaining = n
        
        print(f"[DEBUG] {self.username}: Attempting to receive {n} bytes...")
        
        while remaining > 0:
            try:
                chunk = self.socket.recv(min(remaining, 4096))
                if not chunk:
                    raise ConnectionError("Socket connection broken - no data received")
                data += chunk
                remaining -= len(chunk)
                print(f"[DEBUG] {self.username}: Received {len(chunk)} bytes, {remaining} remaining")
            except socket.timeout:
                print(f"[DEBUG] {self.username}: Socket timeout waiting for data")
                raise
            except Exception as e:
                print(f"[DEBUG] {self.username}: Error in _recv_exact: {e}")
                raise
        
        print(f"[DEBUG] {self.username}: Successfully received all {n} bytes")
        return data

    def _exchange_certificates(self, is_server):
        print(f"[DEBUG] {self.username}: Starting certificate exchange (is_server={is_server})")
        
        cert_bytes = self.certificate.public_bytes(serialization.Encoding.PEM)
        print(f"[DEBUG] {self.username}: Certificate size: {len(cert_bytes)} bytes")

        try:
            if is_server:
                print(f"[DEBUG] {self.username}: SERVER - Waiting to receive client certificate...")
                peer_cert_bytes = self.socket.recv(8192)
                print(f"[DEBUG] {self.username}: SERVER - Received {len(peer_cert_bytes)} bytes")
                
                print(f"[DEBUG] {self.username}: SERVER - Sending our certificate...")
                self.socket.sendall(cert_bytes)
                print(f"[DEBUG] {self.username}: SERVER - Certificate sent")
            else:
                print(f"[DEBUG] {self.username}: CLIENT - Sending our certificate...")
                self.socket.sendall(cert_bytes)
                print(f"[DEBUG] {self.username}: CLIENT - Certificate sent")
                
                print(f"[DEBUG] {self.username}: CLIENT - Waiting to receive server certificate...")
                peer_cert_bytes = self.socket.recv(8192)
                print(f"[DEBUG] {self.username}: CLIENT - Received {len(peer_cert_bytes)} bytes")

            print(f"[DEBUG] {self.username}: Loading peer certificate...")
            self.peer_cert = x509.load_pem_x509_certificate(peer_cert_bytes, default_backend())
            
            for attr in self.peer_cert.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    self.peer_username = attr.value
                    print(f"[DEBUG] {self.username}: Peer username: {self.peer_username}")
                    break
            
            print(f"[DEBUG] {self.username}: Certificate exchange complete")
        except Exception as e:
            print(f"[DEBUG] {self.username}: Certificate exchange FAILED: {e}")
            raise

    def _diffie_hellman(self, is_server):
        print(f"[DEBUG] {self.username}: Starting Diffie-Hellman (is_server={is_server})")
        
        try:
            if is_server:
                print(f"[DEBUG] {self.username}: SERVER - Generating DH parameters (3072-bit)...")
                # Enhanced DH key size (3072 bits)
                params = dh.generate_parameters(
                    generator=2,
                    key_size=3072,
                    backend=default_backend()
                )
                print(f"[DEBUG] {self.username}: SERVER - Parameters generated")

                params_bytes = params.parameter_bytes(
                    serialization.Encoding.PEM,
                    serialization.ParameterFormat.PKCS3
                )
                
                print(f"[DEBUG] {self.username}: SERVER - Signing parameters...")
                sig = self.private_key.sign(
                    params_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print(f"[DEBUG] {self.username}: SERVER - Signature created")

                print(f"[DEBUG] {self.username}: SERVER - Sending params ({len(params_bytes)} bytes)...")
                self.socket.sendall(len(params_bytes).to_bytes(4, "big") + params_bytes)
                
                print(f"[DEBUG] {self.username}: SERVER - Sending signature ({len(sig)} bytes)...")
                self.socket.sendall(len(sig).to_bytes(4, "big") + sig)
                
                self.dh_params = params
                print(f"[DEBUG] {self.username}: SERVER - Parameters sent")
                
            else:  # Client
                print(f"[DEBUG] {self.username}: CLIENT - Receiving DH parameters length...")
                plen = int.from_bytes(self._recv_exact(4), "big")
                print(f"[DEBUG] {self.username}: CLIENT - Parameters length: {plen}")
                
                print(f"[DEBUG] {self.username}: CLIENT - Receiving parameters...")
                params_bytes = self._recv_exact(plen)
                print(f"[DEBUG] {self.username}: CLIENT - Parameters received")

                print(f"[DEBUG] {self.username}: CLIENT - Receiving signature length...")
                slen = int.from_bytes(self._recv_exact(4), "big")
                print(f"[DEBUG] {self.username}: CLIENT - Signature length: {slen}")
                
                print(f"[DEBUG] {self.username}: CLIENT - Receiving signature...")
                sig = self._recv_exact(slen)
                print(f"[DEBUG] {self.username}: CLIENT - Signature received")
                
                print(f"[DEBUG] {self.username}: CLIENT - Verifying signature...")
                self.peer_cert.public_key().verify(
                    sig,
                    params_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print(f"[DEBUG] {self.username}: CLIENT - Signature verified!")

                print(f"[DEBUG] {self.username}: CLIENT - Loading parameters...")
                self.dh_params = serialization.load_pem_parameters(
                    params_bytes,
                    backend=default_backend()
                )
                print(f"[DEBUG] {self.username}: CLIENT - Parameters loaded")

            # Both server and client generate DH key pair
            print(f"[DEBUG] {self.username}: Generating DH private key...")
            self.dh_private = self.dh_params.generate_private_key()
            print(f"[DEBUG] {self.username}: DH private key generated")

            public_bytes = self.dh_private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )

            print(f"[DEBUG] {self.username}: Signing public key...")
            sig = self.private_key.sign(
                public_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            print(f"[DEBUG] {self.username}: Sending public key ({len(public_bytes)} bytes)...")
            self.socket.sendall(len(public_bytes).to_bytes(4, "big") + public_bytes)
            
            print(f"[DEBUG] {self.username}: Sending signature ({len(sig)} bytes)...")
            self.socket.sendall(len(sig).to_bytes(4, "big") + sig)
            print(f"[DEBUG] {self.username}: Public key and signature sent")

            # Receive peer's public key
            print(f"[DEBUG] {self.username}: Receiving peer public key length...")
            plen = int.from_bytes(self._recv_exact(4), "big")
            print(f"[DEBUG] {self.username}: Peer public key length: {plen}")
            
            print(f"[DEBUG] {self.username}: Receiving peer public key...")
            peer_pub = self._recv_exact(plen)

            print(f"[DEBUG] {self.username}: Receiving peer signature length...")
            slen = int.from_bytes(self._recv_exact(4), "big")
            print(f"[DEBUG] {self.username}: Peer signature length: {slen}")
            
            print(f"[DEBUG] {self.username}: Receiving peer signature...")
            peer_sig = self._recv_exact(slen)

            print(f"[DEBUG] {self.username}: Verifying peer signature...")
            self.peer_cert.public_key().verify(
                peer_sig,
                peer_pub,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print(f"[DEBUG] {self.username}: Peer signature verified!")

            print(f"[DEBUG] {self.username}: Loading peer public key...")
            peer_key = serialization.load_pem_public_key(peer_pub, backend=default_backend())
            
            print(f"[DEBUG] {self.username}: Computing shared secret...")
            self.shared_secret = self.dh_private.exchange(peer_key)
            print(f"[DEBUG] {self.username}: Shared secret computed ({len(self.shared_secret)} bytes)")
            
            print(f"[DEBUG] {self.username}: Diffie-Hellman complete!")
        except Exception as e:
            print(f"[DEBUG] {self.username}: Diffie-Hellman FAILED: {e}")
            import traceback
            traceback.print_exc()
            raise

    def _derive_session_key(self):
        """Derive AES-256 session key and HMAC key using PBKDF2"""
        print(f"[DEBUG] {self.username}: Deriving session keys with PBKDF2...")
        
        # Use PBKDF2 to derive stronger keys from shared secret
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for AES-256 + 32 bytes for HMAC
            salt=b'SecureChatSalt2025',  # In production, use random salt
            iterations=100000,
            backend=default_backend()
        )
        
        key_material = kdf.derive(self.shared_secret)
        
        # Split into AES key (32 bytes) and HMAC key (32 bytes)
        self.session_key = key_material[:32]  # AES-256 key
        self.hmac_key = key_material[32:]     # HMAC key
        
        print(f"[DEBUG] {self.username}: AES-256 session key derived (32 bytes)")
        print(f"[DEBUG] {self.username}: HMAC key derived (32 bytes)")

    def _encrypt(self, text):
        """Encrypt text using AES-256 in GCM mode (provides authentication)"""
        iv = os.urandom(12)  # GCM recommends 12-byte IV
        cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(text.encode("utf-8")) + encryptor.finalize()
        
        # GCM provides authentication tag
        return iv, ciphertext, encryptor.tag

    def _decrypt(self, iv, ct, tag):
        """Decrypt text using AES-256 in GCM mode"""
        cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        try:
            plaintext = decryptor.update(ct) + decryptor.finalize()
            return plaintext.decode("utf-8")
        except Exception:
            return None

    def _compute_hmac(self, data):
        """Compute HMAC-SHA256 for message integrity"""
        h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        return h.finalize()

    def _verify_hmac(self, data, received_hmac):
        """Verify HMAC-SHA256"""
        h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        try:
            h.verify(received_hmac)
            return True
        except Exception:
            return False

    def _sign_message(self, message_text):
        """Sign message with RSA-4096"""
        return self.private_key.sign(
            message_text.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def _verify_signature(self, message_text, signature):
        """Verify RSA signature"""
        try:
            self.peer_cert.public_key().verify(
                signature,
                message_text.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

    def _encrypt_log_entry(self, log_text):
        """Encrypt log entry using AES-256"""
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(log_text.encode("utf-8")) + encryptor.finalize()
        tag = encryptor.tag
        
        # Return IV + Tag + Ciphertext as hex
        return (iv + tag + ciphertext).hex()

    def _log_message(self, message):
        def worker():
            try:
                timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                encrypted = self._encrypt_log_entry(f"[{timestamp}] {message}")
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(encrypted + "\n")
            except Exception as e:
                print(f"Logging error: {e}")
        threading.Thread(target=worker, daemon=True).start()

    def decrypt_log_file(self, output_file=None):
        """Decrypt the log file for viewing"""
        if not os.path.exists(self.log_file):
            print("Log file not found")
            return
        
        if output_file is None:
            output_file = self.log_file.replace(".log", "_decrypted.txt")
        
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            
            with open(output_file, "w", encoding="utf-8") as out:
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = bytes.fromhex(line)
                        iv = data[:12]
                        tag = data[12:28]
                        ciphertext = data[28:]
                        
                        cipher = Cipher(
                            algorithms.AES(self.session_key),
                            modes.GCM(iv, tag),
                            backend=default_backend()
                        )
                        decryptor = cipher.decryptor()
                        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                        out.write(plaintext.decode("utf-8") + "\n")
                    except Exception as e:
                        out.write(f"[DECRYPTION ERROR: {e}]\n")
            
            print(f"Decrypted log saved to: {output_file}")
        except Exception as e:
            print(f"Error decrypting log: {e}")

    def send_message(self, text):
        if not self.socket or not self.running:
            self.gui_callback("Error: Not connected")
            return
        try:
            timestamp = datetime.now(timezone.utc).isoformat()
            msg = {
                "seq": self.sequence,
                "text": text,
                "sender": self.username,
                "timestamp": timestamp,
                "signed": self.sign_messages
            }
            
            if self.sign_messages:
                import base64
                msg["signature"] = base64.b64encode(
                    self._sign_message(text)
                ).decode("utf-8")
            
            msg_json = json.dumps(msg)
            
            # Encrypt with AES-256-GCM
            iv, ct, tag = self._encrypt(msg_json)
            
            # Compute HMAC for additional integrity check
            hmac_value = self._compute_hmac(iv + tag + ct)
            
            # Send: HMAC (32 bytes) + IV (12 bytes) + Tag (16 bytes) + Ciphertext
            payload = hmac_value + iv + tag + ct
            
            self.socket.sendall(len(payload).to_bytes(4, "big") + payload)
            self.sequence += 1
            self._log_message(f"[SENT] {text}")
            self._save_message_to_history(self.username, text, timestamp)
        except Exception as e:
            self.gui_callback(f"Send error: {e}")
            self.stop()

    def start_receiving(self):
        self.running = True
        if self.peer_username:
            threading.Thread(
                target=self._load_chat_history,
                daemon=True
            ).start()
        threading.Thread(
            target=self._receive_loop,
            daemon=True
        ).start()

    def _receive_loop(self):
        while self.running:
            try:
                msg_len = int.from_bytes(self._recv_exact(4), "big")
                data = self._recv_exact(msg_len)
                
                # Extract HMAC, IV, Tag, and Ciphertext
                received_hmac = data[:32]
                iv = data[32:44]
                tag = data[44:60]
                ct = data[60:]
                
                # Verify HMAC first
                if not self._verify_hmac(iv + tag + ct, received_hmac):
                    self.gui_callback("⚠️ HMAC VERIFICATION FAILED - Message tampered!")
                    continue
                
                # Decrypt message
                plaintext = self._decrypt(iv, ct, tag)
                if plaintext is None:
                    self.gui_callback("⚠️ Decryption error - message corrupted")
                    continue
                
                msg = json.loads(plaintext)
                sender = msg.get("sender", "Unknown")
                text = msg.get("text", "")
                seq = msg.get("seq", 0)
                timestamp = msg.get("timestamp", "N/A")
                signed = msg.get("signed", False)
                
                # Check for replay attack
                if seq <= self.peer_sequence:
                    self.gui_callback("⚠️ REPLAY ATTACK DETECTED!")
                    continue
                self.peer_sequence = seq
                
                # Verify signature if present
                if signed:
                    import base64
                    signature = base64.b64decode(msg.get("signature", ""))
                    if not self._verify_signature(text, signature):
                        self.gui_callback("⚠️ SIGNATURE VERIFICATION FAILED!")
                        continue
                
                self.gui_callback(f"{sender}: {text}")
                self._log_message(f"[RECV] {sender}: {text}")
                self._save_message_to_history(sender, text, timestamp)
            except ConnectionError:
                self.gui_callback("Connection lost")
                self.stop()
                break
            except Exception as e:
                self.gui_callback(f"Receive error: {e}")
                self.stop()
                break

    def stop(self):
        self.running = False
        self._flush_history_batch()
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.gui_callback("Connection closed")