import tkinter as tk
from tkinter import scrolledtext, messagebox, font
from secure_client import SecureChatClient
from secure_server import SecureChatServer
from config import ChatConfig
from datetime import datetime

class ModernChatGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Wanna Chat — Secure")
        self.root.geometry("500x500")
        self.root.minsize(500, 500)
        self.root.configure(bg='#1e1e2e')
        
        # Modern color scheme
        self.colors = {
            'bg': '#1e1e2e',
            'sidebar': '#181825',
            'chat_bg': '#2e2e3e',
            'input_bg': '#3e3e4e',
            'accent': '#89b4fa',
            'accent_hover': '#74c7ec',
            'text': '#cdd6f4',
            'text_dim': '#a6adc8',
            'border': '#45475a',
            'success': '#a6e3a1',
            'warning': '#f9e2af',
            'error': '#f38ba8',
            'sent_bubble': '#45475a',
            'recv_bubble': '#313244'
        }
        
        self.chat_instance = None
        self.setup_complete = False
        
        # Show setup screen first
        self._create_setup_screen()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def _create_setup_screen(self):
        """Create setup screen in the main window"""
        self.setup_frame = tk.Frame(self.root, bg=self.colors['bg'])
        self.setup_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_font = font.Font(family='Segoe UI', size=20, weight='bold')
        title_label = tk.Label(
            self.setup_frame,
            text="🔒 Wanna Chat",
            font=title_font,
            bg=self.colors['bg'],
            fg=self.colors['accent']
        )
        title_label.pack(pady=(50, 10))
        
        subtitle_font = font.Font(family='Segoe UI', size=10)
        subtitle = tk.Label(
            self.setup_frame,
            text="Secure End-to-End Encrypted Chat",
            font=subtitle_font,
            bg=self.colors['bg'],
            fg=self.colors['text_dim']
        )
        subtitle.pack(pady=(0, 40))
        
        # Setup form container
        form_frame = tk.Frame(self.setup_frame, bg=self.colors['chat_bg'], padx=30, pady=30)
        form_frame.pack(padx=50, pady=20)
        
        label_font = font.Font(family='Segoe UI', size=9)
        entry_font = font.Font(family='Segoe UI', size=10)
        
        # Username
        tk.Label(form_frame, text="Username", font=label_font, 
                bg=self.colors['chat_bg'], fg=self.colors['text_dim']).grid(row=0, column=0, sticky='w', pady=(0, 5))
        self.username_entry = tk.Entry(form_frame, font=entry_font, bg=self.colors['input_bg'], 
                                      fg=self.colors['text'], insertbackground=self.colors['accent'],
                                      relief=tk.FLAT, width=30)
        self.username_entry.grid(row=1, column=0, pady=(0, 15), ipady=5, padx=2)
        self.username_entry.focus_set()
        
        # Role selection
        tk.Label(form_frame, text="Role", font=label_font, 
                bg=self.colors['chat_bg'], fg=self.colors['text_dim']).grid(row=2, column=0, sticky='w', pady=(0, 5))
        
        role_frame = tk.Frame(form_frame, bg=self.colors['chat_bg'])
        role_frame.grid(row=3, column=0, sticky='w', pady=(0, 15))
        
        self.role_var = tk.StringVar(value='s')
        
        server_radio = tk.Radiobutton(role_frame, text="Server", variable=self.role_var, value='s',
                                     bg=self.colors['chat_bg'], fg=self.colors['text'],
                                     selectcolor=self.colors['input_bg'], activebackground=self.colors['chat_bg'],
                                     activeforeground=self.colors['accent'], font=label_font,
                                     command=self._on_role_change)
        server_radio.pack(side=tk.LEFT, padx=(0, 20))
        
        client_radio = tk.Radiobutton(role_frame, text="Client", variable=self.role_var, value='c',
                                     bg=self.colors['chat_bg'], fg=self.colors['text'],
                                     selectcolor=self.colors['input_bg'], activebackground=self.colors['chat_bg'],
                                     activeforeground=self.colors['accent'], font=label_font,
                                     command=self._on_role_change)
        client_radio.pack(side=tk.LEFT)
        
        # Port
        tk.Label(form_frame, text="Port", font=label_font, 
                bg=self.colors['chat_bg'], fg=self.colors['text_dim']).grid(row=4, column=0, sticky='w', pady=(0, 5))
        self.port_entry = tk.Entry(form_frame, font=entry_font, bg=self.colors['input_bg'], 
                                   fg=self.colors['text'], insertbackground=self.colors['accent'],
                                   relief=tk.FLAT, width=30)
        self.port_entry.insert(0, "5000")
        self.port_entry.grid(row=5, column=0, pady=(0, 15), ipady=5, padx=2)
        
        # Server IP (only for client)
        self.server_ip_label = tk.Label(form_frame, text="Server IP Address", font=label_font, 
                                       bg=self.colors['chat_bg'], fg=self.colors['text_dim'])
        self.server_ip_entry = tk.Entry(form_frame, font=entry_font, bg=self.colors['input_bg'], 
                                       fg=self.colors['text'], insertbackground=self.colors['accent'],
                                       relief=tk.FLAT, width=30)
        
        # Connect button
        self.connect_btn = tk.Button(
            form_frame,
            text="Connect",
            command=self._setup_connection,
            bg=self.colors['accent'],
            fg=self.colors['bg'],
            font=font.Font(family='Segoe UI', size=10, weight='bold'),
            relief=tk.FLAT,
            padx=20,
            pady=8,
            cursor='hand2',
            activebackground=self.colors['accent_hover'],
            activeforeground=self.colors['bg']
        )
        self.connect_btn.grid(row=8, column=0, pady=(20, 0))
        
        # Bind Enter key to connect
        self.username_entry.bind("<Return>", lambda e: self._setup_connection())
        self.port_entry.bind("<Return>", lambda e: self._setup_connection())
        self.server_ip_entry.bind("<Return>", lambda e: self._setup_connection())
        
        # Hover effects
        self.connect_btn.bind("<Enter>", lambda e: self.connect_btn.config(bg=self.colors['accent_hover']))
        self.connect_btn.bind("<Leave>", lambda e: self.connect_btn.config(bg=self.colors['accent']))

    def _on_role_change(self):
        """Show/hide server IP field based on role"""
        if self.role_var.get() == 'c':
            self.server_ip_label.grid(row=6, column=0, sticky='w', pady=(0, 5))
            self.server_ip_entry.grid(row=7, column=0, pady=(0, 15), ipady=5, padx=2)
        else:
            self.server_ip_label.grid_forget()
            self.server_ip_entry.grid_forget()

    def _setup_connection(self):
        """Setup connection based on user input"""
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Error", "Username is required", parent=self.root)
            return
        
        role = self.role_var.get()
        
        port_str = self.port_entry.get().strip()
        try:
            port = int(port_str) if port_str else 5000
        except ValueError:
            messagebox.showerror("Error", "Invalid port number", parent=self.root)
            return
        
        if role == 'c':
            server_ip = self.server_ip_entry.get().strip()
            if not server_ip:
                messagebox.showerror("Error", "Server IP is required for client mode", parent=self.root)
                return
        
        # Disable connect button
        self.connect_btn.config(state='disabled', text='Connecting...')
        
        try:
            # Destroy setup screen
            self.setup_frame.destroy()
            
            # Create chat interface
            self._create_chat_widgets()
            
            # Start connection
            if role == 's':
                self.chat_instance = SecureChatServer(port, username, self.display)
                self.display_system(f"🖥️  Starting server on port {port}...")
                import threading
                threading.Thread(target=self.chat_instance.start, daemon=True).start()
            else:
                self.chat_instance = SecureChatClient(server_ip, port, username, self.display)
                self.display_system(f"🔌 Connecting to {server_ip}:{port}...")
                import threading
                threading.Thread(target=self.chat_instance.start, daemon=True).start()
            
            self.setup_complete = True
            
        except Exception as e:
            messagebox.showerror("Error", f"Setup error: {e}", parent=self.root)
            self.root.destroy()

    def _create_chat_widgets(self):
        """Create modern UI widgets for chat"""
        # Main container
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Top bar
        top_bar = tk.Frame(main_container, bg=self.colors['sidebar'], height=50)
        top_bar.pack(fill=tk.X, side=tk.TOP)
        top_bar.pack_propagate(False)
        
        # App title
        title_font = font.Font(family='Segoe UI', size=13, weight='bold')
        title_label = tk.Label(
            top_bar, 
            text="🔒 Wanna Chat",
            font=title_font,
            bg=self.colors['sidebar'],
            fg=self.colors['accent']
        )
        title_label.pack(side=tk.LEFT, padx=10, pady=12)
        
        # Status indicator
        self.status_frame = tk.Frame(top_bar, bg=self.colors['sidebar'])
        self.status_frame.pack(side=tk.RIGHT, padx=10)
        
        self.status_dot = tk.Canvas(self.status_frame, width=10, height=10, 
                                    bg=self.colors['sidebar'], highlightthickness=0)
        self.status_dot.pack(side=tk.LEFT, padx=(0, 5))
        self.status_indicator = self.status_dot.create_oval(2, 2, 8, 8, 
                                                            fill=self.colors['text_dim'], 
                                                            outline='')
        
        status_font = font.Font(family='Segoe UI', size=8)
        self.status_label = tk.Label(
            self.status_frame,
            text="Connecting...",
            font=status_font,
            bg=self.colors['sidebar'],
            fg=self.colors['text_dim']
        )
        self.status_label.pack(side=tk.LEFT)
        
        # Chat area container
        chat_container = tk.Frame(main_container, bg=self.colors['bg'])
        chat_container.pack(fill=tk.BOTH, expand=True, padx=8, pady=(8, 0))
        
        # Chat display with custom styling
        chat_font = font.Font(family='Segoe UI', size=8)
        self.chat = scrolledtext.ScrolledText(
            chat_container,
            state='disabled',
            wrap=tk.WORD,
            font=chat_font,
            bg=self.colors['chat_bg'],
            fg=self.colors['text'],
            insertbackground=self.colors['accent'],
            relief=tk.FLAT,
            padx=8,
            pady=8,
            spacing1=2,
            spacing3=2,
            selectbackground=self.colors['accent'],
            selectforeground=self.colors['bg']
        )
        self.chat.pack(fill=tk.BOTH, expand=True)
        
        # Configure text tags for different message types
        self.chat.tag_config('system', foreground=self.colors['text_dim'], 
                            font=font.Font(family='Segoe UI', size=7, slant='italic'))
        self.chat.tag_config('sent', foreground=self.colors['accent'], 
                            font=font.Font(family='Segoe UI', size=8, weight='bold'))
        self.chat.tag_config('received', foreground=self.colors['success'], 
                            font=font.Font(family='Segoe UI', size=8, weight='bold'))
        self.chat.tag_config('error', foreground=self.colors['error'])
        self.chat.tag_config('warning', foreground=self.colors['warning'])
        self.chat.tag_config('timestamp', foreground=self.colors['text_dim'], 
                            font=font.Font(family='Segoe UI', size=7))
        
        # Input area
        input_container = tk.Frame(main_container, bg=self.colors['bg'], height=55)
        input_container.pack(fill=tk.X, side=tk.BOTTOM, padx=8, pady=(5, 8))
        input_container.pack_propagate(False)
        
        # Input frame with border effect
        input_frame = tk.Frame(input_container, bg=self.colors['border'], padx=1, pady=1)
        input_frame.pack(fill=tk.X)
        
        input_inner = tk.Frame(input_frame, bg=self.colors['input_bg'])
        input_inner.pack(fill=tk.BOTH, expand=True)
        
        # Text entry
        entry_font = font.Font(family='Segoe UI', size=9)
        self.entry = tk.Entry(
            input_inner,
            font=entry_font,
            bg=self.colors['input_bg'],
            fg=self.colors['text'],
            insertbackground=self.colors['accent'],
            relief=tk.FLAT,
            highlightthickness=0,
            selectbackground=self.colors['accent'],
            selectforeground=self.colors['bg']
        )
        self.entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.entry.bind("<Return>", self.send)
        
        # Focus on entry field after a short delay
        self.root.after(100, lambda: self.entry.focus_set())
        
        # Send button
        self.send_btn = tk.Button(
            input_inner,
            text="Send",
            command=self.send,
            bg=self.colors['accent'],
            fg=self.colors['bg'],
            font=font.Font(family='Segoe UI', size=8, weight='bold'),
            relief=tk.FLAT,
            padx=12,
            pady=5,
            cursor='hand2',
            activebackground=self.colors['accent_hover'],
            activeforeground=self.colors['bg']
        )
        self.send_btn.pack(side=tk.RIGHT, padx=6)
        
        # Hover effects for send button
        self.send_btn.bind("<Enter>", lambda e: self.send_btn.config(bg=self.colors['accent_hover']))
        self.send_btn.bind("<Leave>", lambda e: self.send_btn.config(bg=self.colors['accent']))

    def update_status(self, status, color):
        """Update connection status indicator - Thread-safe"""
        def _update():
            self.status_label.config(text=status)
            self.status_dot.itemconfig(self.status_indicator, fill=color)
        
        self.root.after(0, _update)

    def display(self, message):
        """Display message in the chat window with intelligent formatting - Thread-safe"""
        def _display():
            self.chat.config(state='normal')
            
            timestamp = datetime.now().strftime('%H:%M')
            
            # Determine message type and format accordingly
            if message.startswith("Error") or "error" in message.lower():
                self.chat.insert(tk.END, f"⚠️  {message}\n", 'error')
                if "Connection lost" in message or "closed" in message:
                    self.update_status("Disconnected", self.colors['error'])
            elif "Connected" in message or "established" in message:
                self.chat.insert(tk.END, f"✓ {message}\n", 'system')
                self.update_status("Connected", self.colors['success'])
            elif message.startswith("Server listening") or message.startswith("Client connected"):
                self.chat.insert(tk.END, f"✓ {message}\n", 'system')
                self.update_status("Active", self.colors['success'])
            elif "REPLAY ATTACK" in message or "SIGNATURE VERIFICATION FAILED" in message:
                self.chat.insert(tk.END, f"🛡️  {message}\n", 'warning')
            elif message.startswith("You:"):
                # Sent message
                text = message[4:].strip()
                self.chat.insert(tk.END, f"[{timestamp}] ", 'timestamp')
                self.chat.insert(tk.END, "You\n", 'sent')
                self.chat.insert(tk.END, f"{text}\n\n")
            elif ":" in message and not message.startswith("[") and not message.startswith("═"):
                # Received message
                parts = message.split(":", 1)
                sender = parts[0].strip()
                text = parts[1].strip() if len(parts) > 1 else ""
                
                self.chat.insert(tk.END, f"[{timestamp}] ", 'timestamp')
                self.chat.insert(tk.END, f"{sender}\n", 'received')
                self.chat.insert(tk.END, f"{text}\n\n")
            else:
                # System message
                self.chat.insert(tk.END, f"{message}\n", 'system')
            
            self.chat.config(state='disabled')
            self.chat.yview(tk.END)
        
        self.root.after(0, _display)

    def display_system(self, message):
        """Display system message"""
        self.chat.config(state='normal')
        self.chat.insert(tk.END, f"{message}\n", 'system')
        self.chat.config(state='disabled')
        self.chat.yview(tk.END)

    def send(self, event=None):
        """Send message"""
        text = self.entry.get().strip()
        if text and self.chat_instance:
            self.chat_instance.send_message(text)
            self.display(f"You: {text}")
            self.entry.delete(0, tk.END)
        return "break"

    def on_closing(self):
        """Handle window closing"""
        if self.chat_instance:
            self.chat_instance.stop()
        self.root.destroy()

if __name__ == "__main__":
    ModernChatGUI()