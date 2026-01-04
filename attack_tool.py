import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import threading
import time
from datetime import datetime

class AttackTestingTool:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Wanna Chat - Attack Testing Tool")
        self.root.geometry("900x750")
        self.root.configure(bg='#2b2b2b')
        
        self.intercepted_messages = []
        self.proxy_socket = None
        self.client_socket = None
        self.server_socket = None
        self.running = False
        self.forward_enabled = True
        self.delay_enabled = False
        self.connection_established = False
        
        self._create_ui()
        self.root.mainloop()
    
    def _create_ui(self):
        # Title
        title = tk.Label(
            self.root, 
            text="🔓 Attack Testing Tool",
            font=('Segoe UI', 16, 'bold'),
            bg='#2b2b2b',
            fg='#ff6b6b'
        )
        title.pack(pady=10)
        
        # Instructions Frame
        instr_frame = tk.LabelFrame(
            self.root,
            text="Quick Start Instructions",
            bg='#3b3b3b',
            fg='#00ff00',
            font=('Segoe UI', 9, 'bold'),
            padx=10,
            pady=5
        )
        instr_frame.pack(fill=tk.X, padx=20, pady=5)
        
        instructions = """CORRECT SETUP (Client must connect to same port as usual):
1. Start Server on DIFFERENT port (e.g., 5555 instead of 5000)
2. Start Proxy listening on port 5000 (normal client port)
3. Proxy forwards to server on port 5555
4. Client connects to port 5000 (gets intercepted)

Example:
- Server: Port 5555
- Proxy: Listen 5000 → Forward to 127.0.0.1:5555
- Client: Connects to port 5000 (thinks it's talking to server)"""
        
        tk.Label(
            instr_frame,
            text=instructions,
            bg='#3b3b3b',
            fg='#ffffff',
            font=('Courier', 8),
            justify=tk.LEFT
        ).pack()
        
        # Configuration Frame
        config_frame = tk.LabelFrame(
            self.root,
            text="Proxy Configuration",
            bg='#3b3b3b',
            fg='#ffffff',
            font=('Segoe UI', 10, 'bold'),
            padx=10,
            pady=10
        )
        config_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Target Server
        tk.Label(config_frame, text="Target Server:", bg='#3b3b3b', fg='#ffffff').grid(row=0, column=0, sticky='w', pady=5)
        self.server_ip = tk.Entry(config_frame, width=20)
        self.server_ip.insert(0, "127.0.0.1")
        self.server_ip.grid(row=0, column=1, padx=5)
        
        tk.Label(config_frame, text="Port:", bg='#3b3b3b', fg='#ffffff').grid(row=0, column=2, sticky='w')
        self.server_port = tk.Entry(config_frame, width=10)
        self.server_port.insert(0, "5555")
        self.server_port.grid(row=0, column=3, padx=5)
        
        # Proxy Port
        tk.Label(config_frame, text="Proxy Listens On:", bg='#3b3b3b', fg='#ffffff').grid(row=1, column=0, sticky='w', pady=5)
        self.proxy_port = tk.Entry(config_frame, width=10)
        self.proxy_port.insert(0, "5000")
        self.proxy_port.grid(row=1, column=1, padx=5, sticky='w')
        
        # Status Label
        self.connection_status = tk.Label(
            config_frame,
            text="● Not Connected",
            bg='#3b3b3b',
            fg='#ff6b6b',
            font=('Segoe UI', 9, 'bold')
        )
        self.connection_status.grid(row=0, column=4, padx=10)
        
        # Start/Stop Proxy
        self.proxy_btn = tk.Button(
            config_frame,
            text="Start Proxy",
            command=self.toggle_proxy,
            bg='#4caf50',
            fg='#ffffff',
            font=('Segoe UI', 9, 'bold'),
            cursor='hand2',
            padx=20,
            width=15
        )
        self.proxy_btn.grid(row=1, column=2, columnspan=2, pady=5)
        
        # Attack Selection Frame
        attack_frame = tk.LabelFrame(
            self.root,
            text="Attack Types (Select message first for some attacks)",
            bg='#3b3b3b',
            fg='#ffffff',
            font=('Segoe UI', 10, 'bold'),
            padx=10,
            pady=10
        )
        attack_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Attack Buttons - arranged in 3 columns
        attacks = [
            ("1. View MITM Status", self.mitm_attack),
            ("2. Replay Attack", self.replay_attack),
            ("3. Message Tampering", self.tamper_attack),
            ("4. Drop Next Message", self.drop_attack),
            ("5. Toggle Delay (5s)", self.delay_attack),
            ("6. Cert Substitution Info", self.cert_attack)
        ]
        
        for i, (name, cmd) in enumerate(attacks):
            btn = tk.Button(
                attack_frame,
                text=name,
                command=cmd,
                bg='#ff9800',
                fg='#ffffff',
                font=('Segoe UI', 9),
                width=22,
                cursor='hand2'
            )
            btn.grid(row=i//3, column=i%3, padx=5, pady=5)
        
        # Intercepted Messages Frame
        messages_frame = tk.LabelFrame(
            self.root,
            text="Intercepted Messages (Click to select)",
            bg='#3b3b3b',
            fg='#ffffff',
            font=('Segoe UI', 10, 'bold'),
            padx=10,
            pady=10
        )
        messages_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Message List with scrollbar
        list_frame = tk.Frame(messages_frame, bg='#2b2b2b')
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.message_list = tk.Listbox(
            list_frame,
            bg='#2b2b2b',
            fg='#00ff00',
            font=('Courier', 9),
            selectmode=tk.SINGLE,
            yscrollcommand=scrollbar.set
        )
        self.message_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.message_list.yview)
        
        # Log Frame
        log_frame = tk.LabelFrame(
            self.root,
            text="Attack Log",
            bg='#3b3b3b',
            fg='#ffffff',
            font=('Segoe UI', 10, 'bold')
        )
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        self.log = scrolledtext.ScrolledText(
            log_frame,
            height=10,
            bg='#1e1e1e',
            fg='#00ff00',
            font=('Courier', 9)
        )
        self.log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Initial log message
        self.log_message("🔧 Ready to start. Click 'Start Proxy' when server is running.")
    
    def log_message(self, msg):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.log.see(tk.END)
        self.root.update_idletasks()
    
    def update_connection_status(self, connected):
        if connected:
            self.connection_status.config(text="● Connected", fg='#00ff00')
            self.connection_established = True
        else:
            self.connection_status.config(text="● Not Connected", fg='#ff6b6b')
            self.connection_established = False
    
    def toggle_proxy(self):
        if not self.running:
            self.start_proxy()
        else:
            self.stop_proxy()
    
    def start_proxy(self):
        try:
            port = int(self.proxy_port.get())
            self.running = True
            self.proxy_btn.config(text="Stop Proxy", bg='#f44336')
            
            # Disable configuration while running
            self.server_ip.config(state='disabled')
            self.server_port.config(state='disabled')
            self.proxy_port.config(state='disabled')
            
            threading.Thread(target=self._run_proxy, args=(port,), daemon=True).start()
            self.log_message(f"✓ Proxy started on port {port}")
            self.log_message(f"→ Waiting for client connection...")
            self.log_message(f"→ Client should connect to: 127.0.0.1:{port}")
        except Exception as e:
            self.running = False
            self.proxy_btn.config(text="Start Proxy", bg='#4caf50')
            messagebox.showerror("Error", f"Failed to start proxy: {e}")
    
    def stop_proxy(self):
        self.running = False
        
        # Close all sockets
        for sock in [self.proxy_socket, self.client_socket, self.server_socket]:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        
        self.proxy_socket = None
        self.client_socket = None
        self.server_socket = None
        
        # Re-enable configuration
        self.server_ip.config(state='normal')
        self.server_port.config(state='normal')
        self.proxy_port.config(state='normal')
        
        self.proxy_btn.config(text="Start Proxy", bg='#4caf50')
        self.update_connection_status(False)
        self.log_message("✗ Proxy stopped")
    
    def _run_proxy(self, port):
        """Main proxy loop"""
        try:
            self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.proxy_socket.bind(('0.0.0.0', port))
            self.proxy_socket.listen(1)
            self.proxy_socket.settimeout(1.0)
            
            self.log_message("⏳ Proxy listening, waiting for client...")
            
            # Wait for client connection
            while self.running:
                try:
                    self.client_socket, client_addr = self.proxy_socket.accept()
                    self.log_message(f"✓ Client connected from {client_addr[0]}:{client_addr[1]}")
                    break
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.log_message(f"✗ Accept error: {e}")
                    return
            
            if not self.running:
                return
            
            # Connect to real server
            server_ip = self.server_ip.get()
            server_port = int(self.server_port.get())
            
            try:
                self.log_message(f"→ Connecting to server {server_ip}:{server_port}...")
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.settimeout(10)
                self.server_socket.connect((server_ip, server_port))
                self.log_message(f"✓ Connected to server!")
                self.log_message("=" * 50)
                self.log_message("🎯 MITM POSITION ESTABLISHED!")
                self.log_message("=" * 50)
                self.update_connection_status(True)
                
            except Exception as e:
                self.log_message(f"✗ Failed to connect to server: {e}")
                self.log_message("→ Make sure the chat server is running first!")
                self.stop_proxy()
                return
            
            # Start forwarding threads
            threading.Thread(
                target=self._forward, 
                args=(self.client_socket, self.server_socket, "Client→Server"),
                daemon=True
            ).start()
            
            threading.Thread(
                target=self._forward, 
                args=(self.server_socket, self.client_socket, "Server→Client"),
                daemon=True
            ).start()
            
        except Exception as e:
            self.log_message(f"✗ Proxy error: {e}")
            self.stop_proxy()
    
    def _forward(self, source, destination, direction):
        """Forward data between sockets and intercept"""
        source.settimeout(0.5)
        
        try:
            while self.running:
                try:
                    data = source.recv(4096)
                    
                    if not data:
                        self.log_message(f"✗ Connection closed: {direction}")
                        break
                    
                    # Store intercepted message
                    msg_info = {
                        'direction': direction,
                        'data': data,
                        'timestamp': datetime.now(),
                        'size': len(data)
                    }
                    self.intercepted_messages.append(msg_info)
                    
                    # Update UI in main thread
                    self.root.after(0, self._add_message_to_list, msg_info)
                    self.root.after(0, self.log_message, 
                                  f"📦 Intercepted: {direction} ({len(data)} bytes)")
                    
                    # Apply delay if enabled
                    if self.delay_enabled:
                        time.sleep(5)
                        self.root.after(0, self.log_message, 
                                      f"⏰ Delayed message by 5s: {direction}")
                    
                    # Forward data only if forwarding is enabled
                    if self.forward_enabled:
                        destination.sendall(data)
                    else:
                        self.root.after(0, self.log_message, 
                                      f"🗑️ DROPPED: {direction}")
                        self.forward_enabled = True  # Re-enable after dropping
                
                except socket.timeout:
                    continue
                    
                except Exception as e:
                    if self.running:
                        self.root.after(0, self.log_message, 
                                      f"✗ Forward error ({direction}): {e}")
                    break
                    
        except Exception as e:
            if self.running:
                self.root.after(0, self.log_message, 
                              f"✗ Fatal forward error ({direction}): {e}")
        
        finally:
            self.root.after(0, self.update_connection_status, False)
    
    def _add_message_to_list(self, msg_info):
        timestamp = msg_info['timestamp'].strftime('%H:%M:%S.%f')[:-3]
        display = f"[{timestamp}] {msg_info['direction']:15} - {msg_info['size']:5} bytes"
        self.message_list.insert(tk.END, display)
        self.message_list.see(tk.END)
    
    # ==================== ATTACK METHODS ====================
    
    def mitm_attack(self):
        """Man-in-the-Middle Attack Status"""
        if not self.connection_established:
            messagebox.showwarning("Not Connected", 
                                 "Start the proxy and establish a connection first!")
            return
        
        self.log_message("=" * 50)
        self.log_message("🔴 MITM ATTACK STATUS")
        self.log_message("=" * 50)
        self.log_message("✓ Position: Between client and server")
        self.log_message(f"✓ Intercepted: {len(self.intercepted_messages)} messages")
        self.log_message("ℹ️  All traffic is visible but encrypted")
        self.log_message("=" * 50)
        
        messagebox.showinfo(
            "MITM Attack Active",
            f"Man-in-the-Middle attack is active!\n\n"
            f"Messages intercepted: {len(self.intercepted_messages)}\n\n"
            f"The proxy can see all traffic, but:\n"
            f"• Messages are encrypted with DES\n"
            f"• Session key is unknown to attacker\n"
            f"• Content remains confidential\n\n"
            f"Expected: Messages readable in chat but encrypted in transit."
        )
    
    def replay_attack(self):
        """Replay Attack - Resend captured message"""
        if not self.connection_established:
            messagebox.showwarning("Not Connected", "Establish a connection first!")
            return
            
        if not self.intercepted_messages:
            messagebox.showwarning("No Messages", 
                                 "No messages intercepted yet! Send some messages first.")
            return
        
        selection = self.message_list.curselection()
        if not selection:
            messagebox.showwarning("No Selection", 
                                 "Please select a message from the list first!")
            return
        
        idx = selection[0]
        msg = self.intercepted_messages[idx]
        
        try:
            self.log_message("=" * 50)
            self.log_message("🔴 REPLAY ATTACK INITIATED")
            self.log_message("=" * 50)
            
            if msg['direction'] == "Client→Server" and self.server_socket:
                self.server_socket.sendall(msg['data'])
                self.log_message(f"→ Replayed message to SERVER")
                target = "server"
            elif msg['direction'] == "Server→Client" and self.client_socket:
                self.client_socket.sendall(msg['data'])
                self.log_message(f"→ Replayed message to CLIENT")
                target = "client"
            else:
                self.log_message("✗ Cannot replay - connection lost")
                return
            
            self.log_message(f"→ Expected: {target.upper()} rejects due to old sequence number")
            self.log_message("=" * 50)
            
            messagebox.showinfo(
                "Replay Attack Executed",
                f"Message replayed to {target}!\n\n"
                f"The application should detect and reject this\n"
                f"replayed message due to sequence number validation.\n\n"
                f"Check the chat window for:\n"
                f"'⚠️ REPLAY ATTACK DETECTED!' warning"
            )
        except Exception as e:
            self.log_message(f"✗ Replay failed: {e}")
            messagebox.showerror("Error", f"Replay attack failed: {e}")
    
    def tamper_attack(self):
        """Message Tampering Attack"""
        if not self.connection_established:
            messagebox.showwarning("Not Connected", "Establish a connection first!")
            return
            
        if not self.intercepted_messages:
            messagebox.showwarning("No Messages", "No messages intercepted yet!")
            return
        
        selection = self.message_list.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a message first!")
            return
        
        idx = selection[0]
        msg = self.intercepted_messages[idx]
        
        try:
            self.log_message("=" * 50)
            self.log_message("🔴 TAMPERING ATTACK INITIATED")
            self.log_message("=" * 50)
            
            # Tamper with the data (flip some bits)
            tampered_data = bytearray(msg['data'])
            if len(tampered_data) > 20:
                tamper_pos = len(tampered_data) // 2
                original_byte = tampered_data[tamper_pos]
                tampered_data[tamper_pos] ^= 0xFF
                self.log_message(f"→ Flipped bits at position {tamper_pos}")
                self.log_message(f"→ Original byte: 0x{original_byte:02X}, Tampered: 0x{tampered_data[tamper_pos]:02X}")
            
            if msg['direction'] == "Client→Server" and self.server_socket:
                self.server_socket.sendall(bytes(tampered_data))
                self.log_message(f"→ Sent tampered message to SERVER")
                target = "server"
            elif msg['direction'] == "Server→Client" and self.client_socket:
                self.client_socket.sendall(bytes(tampered_data))
                self.log_message(f"→ Sent tampered message to CLIENT")
                target = "client"
            else:
                self.log_message("✗ Cannot tamper - connection lost")
                return
            
            self.log_message(f"→ Expected: Decryption failure or malformed data")
            self.log_message("=" * 50)
            
            messagebox.showinfo(
                "Tampering Attack Executed",
                f"Tampered message sent to {target}!\n\n"
                f"The application should detect tampering through:\n"
                f"1. Decryption failure (corrupted ciphertext)\n"
                f"2. Invalid JSON structure\n\n"
                f"Check for error messages in the chat window."
            )
        except Exception as e:
            self.log_message(f"✗ Tamper failed: {e}")
            messagebox.showerror("Error", f"Tampering attack failed: {e}")
    
    def drop_attack(self):
        """Message Drop Attack"""
        if not self.connection_established:
            messagebox.showwarning("Not Connected", "Establish a connection first!")
            return
            
        self.forward_enabled = False
        self.log_message("=" * 50)
        self.log_message("🔴 DROP ATTACK ARMED")
        self.log_message("=" * 50)
        self.log_message("→ Next message will be DROPPED")
        self.log_message("→ Simulating packet loss")
        self.log_message("=" * 50)
        
        messagebox.showinfo(
            "Drop Attack Armed",
            "Next message will be dropped!\n\n"
            "This simulates network packet loss.\n"
            "Send a message now to see it dropped.\n\n"
            "Expected: Message never arrives at destination."
        )
    
    def delay_attack(self):
        """Toggle Delay Attack"""
        if not self.connection_established:
            messagebox.showwarning("Not Connected", "Establish a connection first!")
            return
            
        self.delay_enabled = not self.delay_enabled
        
        if self.delay_enabled:
            self.log_message("=" * 50)
            self.log_message("🔴 DELAY ATTACK ENABLED")
            self.log_message("=" * 50)
            self.log_message("→ All messages delayed by 5 seconds")
            self.log_message("=" * 50)
            
            messagebox.showinfo(
                "Delay Attack Enabled",
                "Messages will be delayed by 5 seconds!\n\n"
                "This tests if the application handles timing issues.\n"
                "Messages should still be accepted.\n\n"
                "Click again to disable."
            )
        else:
            self.log_message("✓ DELAY ATTACK DISABLED")
            messagebox.showinfo(
                "Delay Attack Disabled",
                "Messages will be forwarded immediately."
            )
    
    def cert_attack(self):
        """Certificate Substitution Attack Info"""
        self.log_message("=" * 50)
        self.log_message("🔴 CERTIFICATE SUBSTITUTION ATTACK")
        self.log_message("=" * 50)
        self.log_message("ℹ️  This attack must occur during handshake")
        self.log_message("ℹ️  Would require proxy to intercept certificate exchange")
        self.log_message("=" * 50)
        
        messagebox.showinfo(
            "Certificate Substitution Attack",
            "This attack attempts to substitute certificates\n"
            "during the initial handshake.\n\n"
            "Protection Mechanisms:\n"
            "• DH parameters are signed with RSA private key\n"
            "• Signature verification prevents substitution\n"
            "• Man-in-the-middle cannot forge signatures\n\n"
            "To test:\n"
            "1. Modify proxy to intercept handshake\n"
            "2. Replace certificate with attacker's cert\n"
            "3. Signature verification should fail\n\n"
            "Expected: Handshake rejection"
        )

if __name__ == "__main__":
    AttackTestingTool()