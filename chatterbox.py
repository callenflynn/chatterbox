"""
Chatterbox - Peer-to-Peer Chat Application
A serverless P2P chat app with network discovery and custom addressing
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import json
import hashlib
import time
import uuid
import subprocess
import platform
from datetime import datetime
import os
import sys
import base64
import secrets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

class SecureChat:
    def __init__(self):
        self.shared_key = None
        self.my_private_key = None
        self.peer_public_key = None
        self.session_key = None
        self.is_encrypted = False
        
    def generate_dh_keypair(self):
        self.my_private_key = secrets.randbits(256)
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        g = 2
        self.my_public_key = pow(g, self.my_private_key, p)
        return self.my_public_key
        
    def compute_shared_secret(self, peer_public_key):
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        shared_secret = pow(peer_public_key, self.my_private_key, p)
        self.session_key = PBKDF2(str(shared_secret).encode(), b'chatterbox_salt', 32, count=100000, hmac_hash_module=SHA256)
        self.is_encrypted = True
        return self.get_key_fingerprint()
        
    def get_key_fingerprint(self):
        if self.session_key:
            return hashlib.sha256(self.session_key).hexdigest()[:16].upper()
        return None
        
    def encrypt_message(self, message):
        if not self.session_key:
            return message
        cipher = AES.new(self.session_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')
        
    def decrypt_message(self, encrypted_message):
        if not self.session_key:
            return encrypted_message
        try:
            encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))
            nonce = encrypted_data[:16]
            tag = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            cipher = AES.new(self.session_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode('utf-8')
        except:
            return "[DECRYPTION FAILED]"
class ChatterboxApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Chatterbox - P2P Chat")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)
        try:
            icon_path = os.path.join(os.path.dirname(__file__), "assets", "ChatterBox.png")
            if os.path.exists(icon_path):
                icon = tk.PhotoImage(file=icon_path)
                self.root.iconphoto(True, icon)
        except Exception as e:
            print(f"Could not load icon: {e}")
        self.display_name = "Anonymous"
        self.local_ip = ""
        self.public_ip = ""
        self.is_connected = False
        self.peer_socket = None
        self.server_socket = None
        self.discovery_socket = None
        self.peer_info = None
        self.discovered_devices = {}
        self.chat_history = {}
        self.dark_mode = False
        self.show_timestamps = True
        self.secure_chat = SecureChat()
        self.DISCOVERY_PORT = 41234
        self.CHAT_PORT = 41235
        self.MAGIC_BYTES = b"CHATTERBOX_DISCOVERY"
        self.find_available_ports()
        self.load_profile()
    def find_available_ports(self):
        """Find available ports for this instance"""
        for port_offset in range(10):
            test_port = self.CHAT_PORT + port_offset
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                test_socket.bind(('', test_port))
                test_socket.close()
                self.CHAT_PORT = test_port
                print(f"Using chat port: {self.CHAT_PORT}")
                break
            except OSError:
                continue
        for port_offset in range(10):
            test_port = self.DISCOVERY_PORT + port_offset
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                test_socket.bind(('', test_port))
                test_socket.close()
                self.DISCOVERY_PORT = test_port
                print(f"Using discovery port: {self.DISCOVERY_PORT}")
                break
            except OSError:
                continue
        self.get_local_ip()
        self.get_public_ip()
        self.load_chat_history()
        self.setup_gui()
        self.start_network_services()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    def load_profile(self):
        """Load user profile from config file"""
        config_file = os.path.join(os.path.expanduser("~"), ".chatterbox_config.json")
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    self.display_name = config.get('display_name', 'Anonymous')
                    self.dark_mode = config.get('dark_mode', False)
                    self.show_timestamps = config.get('show_timestamps', True)
        except Exception as e:
            print(f"Error loading config: {e}")
    def save_profile(self):
        """Save user profile to config file"""
        config_file = os.path.join(os.path.expanduser("~"), ".chatterbox_config.json")
        try:
            config = {
                'display_name': self.display_name,
                'dark_mode': self.dark_mode,
                'show_timestamps': self.show_timestamps
            }
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")
    def get_public_ip(self):
        """Get the public IP address of this machine"""
        try:
            import urllib.request
            services = [
                'https://ipv4.icanhazip.com',
                'https://api.ipify.org',
                'https://checkip.amazonaws.com',
                'https://ipinfo.io/ip'
            ]
            for service in services:
                try:
                    with urllib.request.urlopen(service, timeout=5) as response:
                        self.public_ip = response.read().decode().strip()
                        break
                except:
                    continue
            if not self.public_ip:
                self.public_ip = "Unable to determine"
        except Exception as e:
            print(f"Error getting public IP: {e}")
            self.public_ip = "Unable to determine"
    def get_local_ip(self):
        """Get the local IP address of this machine"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                self.local_ip = s.getsockname()[0]
        except Exception:
            try:
                self.local_ip = socket.gethostbyname(socket.gethostname())
            except Exception:
                self.local_ip = "127.0.0.1"
    def generate_chatterbox_address(self):
        """Generate a simple unique identifier for the user"""
        try:
            machine_id = str(uuid.getnode())
            address_hash = hashlib.md5(machine_id.encode()).hexdigest()[:8]
            return f"user_{address_hash}"
        except Exception:
            random_part = hashlib.md5(str(uuid.getnode()).encode()).hexdigest()[:8]
            return f"user_{random_part}"
    def load_chat_history(self):
        """Load chat history from config file"""
        history_file = os.path.join(os.path.expanduser("~"), ".chatterbox_history.json")
        try:
            if os.path.exists(history_file):
                with open(history_file, 'r') as f:
                    self.chat_history = json.load(f)
        except Exception as e:
            print(f"Error loading chat history: {e}")
            self.chat_history = {}
    def save_chat_history(self):
        """Save chat history to config file"""
        history_file = os.path.join(os.path.expanduser("~"), ".chatterbox_history.json")
        try:
            with open(history_file, 'w') as f:
                json.dump(self.chat_history, f, indent=2)
        except Exception as e:
            print(f"Error saving chat history: {e}")
    def update_peer_status(self, peer_address, is_online):
        """Update the online status of a peer"""
        if peer_address not in self.chat_history:
            self.chat_history[peer_address] = {
                'display_name': 'Unknown',
                'last_seen': time.time(),
                'is_online': is_online,
                'message_count': 0
            }
        else:
            self.chat_history[peer_address]['is_online'] = is_online
            self.chat_history[peer_address]['last_seen'] = time.time()
        self.save_chat_history()
    def setup_gui(self):
        """Setup the main GUI"""
        self.apply_theme()
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.setup_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.setup_frame, text="💬 Connect")
        self.chat_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.chat_frame, text="🗨️ Chat")
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="⚙️ Settings")
        self.setup_setup_tab()
        self.setup_chat_tab()
        self.setup_settings_tab()
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.notebook.tab(1, state="disabled")
    def setup_setup_tab(self):
        """Setup the connection and discovery tab"""
        profile_frame = ttk.LabelFrame(self.setup_frame, text="👤 Your Profile", padding=15)
        profile_frame.pack(fill=tk.X, padx=15, pady=10)
        name_frame = ttk.Frame(profile_frame)
        name_frame.pack(fill=tk.X, pady=5)
        ttk.Label(name_frame, text="Display Name:", font=("TkDefaultFont", 10, "bold")).pack(side=tk.LEFT)
        self.name_entry = ttk.Entry(name_frame, width=25, font=("TkDefaultFont", 10))
        self.name_entry.insert(0, self.display_name)
        self.name_entry.pack(side=tk.RIGHT)
        self.name_entry.bind('<FocusOut>', self.on_name_change)
        ip_frame = ttk.LabelFrame(profile_frame, text="🌐 Network Information", padding=10)
        ip_frame.pack(fill=tk.X, pady=(10, 0))
        local_frame = ttk.Frame(ip_frame)
        local_frame.pack(fill=tk.X, pady=2)
        ttk.Label(local_frame, text="Local IP:", font=("TkDefaultFont", 9)).pack(side=tk.LEFT)
        self.ip_label = ttk.Label(local_frame, text=self.local_ip, foreground="blue", font=("TkDefaultFont", 9, "bold"))
        self.ip_label.pack(side=tk.RIGHT)
        public_frame = ttk.Frame(ip_frame)
        public_frame.pack(fill=tk.X, pady=2)
        ttk.Label(public_frame, text="Public IP:", font=("TkDefaultFont", 9)).pack(side=tk.LEFT)
        self.public_ip_label = ttk.Label(public_frame, text=self.public_ip, foreground="green", font=("TkDefaultFont", 9, "bold"))
        self.public_ip_label.pack(side=tk.RIGHT)
        refresh_btn = ttk.Button(ip_frame, text="🔄 Refresh IPs", command=self.refresh_ip)
        refresh_btn.pack(pady=(5, 0))
        connection_frame = ttk.LabelFrame(self.setup_frame, text="🔗 Connection Options", padding=15)
        connection_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        mode_frame = ttk.Frame(connection_frame)
        mode_frame.pack(fill=tk.X, pady=(0, 15))
        self.mode_var = tk.StringVar(value="discover")
        mode_buttons = [
            ("🔍 Auto-Discover", "discover"),
            ("🌐 Manual IP", "manual")
        ]
        for text, value in mode_buttons:
            btn = ttk.Radiobutton(mode_frame, text=text, variable=self.mode_var,
                                value=value, command=self.on_mode_change)
            btn.pack(side=tk.LEFT, padx=(0, 20))
        self.discover_frame = ttk.Frame(connection_frame)
        self.discover_frame.pack(fill=tk.BOTH, expand=True)
        discover_controls = ttk.Frame(self.discover_frame)
        discover_controls.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(discover_controls, text="🔄 Scan Network",
                  command=self.refresh_discovery).pack(side=tk.LEFT)
        self.devices_tree = ttk.Treeview(self.discover_frame, columns=("name", "ip"),
                                        show="headings", height=6)
        self.devices_tree.heading("name", text="👤 Display Name")
        self.devices_tree.heading("ip", text="🌐 IP Address")
        self.devices_tree.column("name", width=200)
        self.devices_tree.column("ip", width=150)
        devices_scroll = ttk.Scrollbar(self.discover_frame, orient=tk.VERTICAL, command=self.devices_tree.yview)
        self.devices_tree.configure(yscrollcommand=devices_scroll.set)
        self.devices_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        devices_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.devices_tree.bind('<Double-1>', self.on_device_select)
        self.manual_frame = ttk.Frame(connection_frame)
        manual_input_frame = ttk.Frame(self.manual_frame)
        manual_input_frame.pack(pady=20)
        ttk.Label(manual_input_frame, text="IP Address:", font=("TkDefaultFont", 10, "bold")).pack(pady=(0, 5))
        ip_entry_frame = ttk.Frame(manual_input_frame)
        ip_entry_frame.pack()
        self.ip_entry = ttk.Entry(ip_entry_frame, width=20, font=("TkDefaultFont", 11))
        self.ip_entry.pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(ip_entry_frame, text="🔗 Connect",
                  command=self.connect_manual_ip).pack(side=tk.LEFT)
        self.on_mode_change()
    def setup_settings_tab(self):
        """Setup the settings tab"""
        theme_frame = ttk.LabelFrame(self.settings_frame, text="🎨 Appearance", padding=15)
        theme_frame.pack(fill=tk.X, padx=15, pady=10)
        self.dark_mode_var = tk.BooleanVar(value=self.dark_mode)
        dark_mode_check = ttk.Checkbutton(theme_frame, text="🌙 Dark Mode",
                                         variable=self.dark_mode_var,
                                         command=self.toggle_dark_mode)
        dark_mode_check.pack(anchor=tk.W, pady=(0, 5))
        self.show_timestamps_var = tk.BooleanVar(value=self.show_timestamps)
        timestamps_check = ttk.Checkbutton(theme_frame, text="🕒 Show Message Timestamps",
                                          variable=self.show_timestamps_var,
                                          command=self.toggle_timestamps)
        timestamps_check.pack(anchor=tk.W)
        chat_frame = ttk.LabelFrame(self.settings_frame, text="💬 Chat Management", padding=15)
        chat_frame.pack(fill=tk.X, padx=15, pady=10)
        history_info_frame = ttk.Frame(chat_frame)
        history_info_frame.pack(fill=tk.X, pady=(0, 10))
        chat_count = len(self.chat_history)
        self.chat_count_label = ttk.Label(history_info_frame, text=f"📊 Total conversations: {chat_count}")
        self.chat_count_label.pack(anchor=tk.W)
        history_display_frame = ttk.LabelFrame(chat_frame, text="📚 Chat History", padding=10)
        history_display_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.settings_history_tree = ttk.Treeview(history_display_frame, columns=("name", "status", "last_seen"),
                                                 show="headings", height=6)
        self.settings_history_tree.heading("name", text="👤 Display Name")
        self.settings_history_tree.heading("status", text="📶 Status")
        self.settings_history_tree.heading("last_seen", text="🕒 Last Seen")
        self.settings_history_tree.column("name", width=150)
        self.settings_history_tree.column("status", width=80)
        self.settings_history_tree.column("last_seen", width=120)
        settings_history_scroll = ttk.Scrollbar(history_display_frame, orient=tk.VERTICAL,
                                               command=self.settings_history_tree.yview)
        self.settings_history_tree.configure(yscrollcommand=settings_history_scroll.set)
        self.settings_history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        settings_history_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        delete_frame = ttk.LabelFrame(chat_frame, text="⚠️ Danger Zone", padding=10)
        delete_frame.pack(fill=tk.X)
        ttk.Label(delete_frame, text="⚠️ This will permanently delete all chat history",
                 foreground="red", font=("TkDefaultFont", 9)).pack(anchor=tk.W, pady=(0, 5))
        delete_btn = ttk.Button(delete_frame, text="🗑️ Delete All Chats",
                               command=self.delete_all_chats)
        delete_btn.pack(anchor=tk.W)
        self.update_settings_history_display()
    def toggle_timestamps(self):
        """Toggle timestamp display setting"""
        self.show_timestamps = self.show_timestamps_var.get()
        self.save_profile()
        self.update_status("Timestamp setting updated")
    def toggle_dark_mode(self):
        """Toggle dark mode theme"""
        self.dark_mode = self.dark_mode_var.get()
        self.save_profile()
        self.apply_theme()
        self.update_status("Theme updated successfully")
    def update_existing_widgets(self):
        """Update existing widgets to match current theme - DEPRECATED"""
        pass
    def get_theme_colors(self):
        """Get colors for current theme"""
        if self.dark_mode:
            return {
                'bg': '#1a1a1a',
                'fg': '#e5e5e5',
                'entry_bg': '#2c2c2c',
                'entry_fg': '#ffffff',
                'button_bg': '#4a4a4a',
                'button_fg': '#ffffff',
                'select_bg': '#0066cc',
                'select_fg': '#ffffff',
                'border': '#404040',
                'highlight': '#3a3a3a',
                'active': '#5a5a5a',
                'chat_bg': '#1e1e1e',
                'sent_bubble': '#0066cc',
                'received_bubble': '#2c2c2c',
                'sent_text': '#ffffff',
                'received_text': '#e5e5e5'
            }
        else:
            return {
                'bg': '#f8f9fa',
                'fg': '#212529',
                'entry_bg': '#ffffff',
                'entry_fg': '#212529',
                'button_bg': '#e9ecef',
                'button_fg': '#495057',
                'select_bg': '#0066cc',
                'select_fg': '#ffffff',
                'border': '#dee2e6',
                'highlight': '#f1f3f4',
                'active': '#e2e6ea',
                'chat_bg': '#ffffff',
                'sent_bubble': '#0066cc',
                'received_bubble': '#e9ecef',
                'sent_text': '#ffffff',
                'received_text': '#212529'
            }
    def apply_theme(self):
        """Apply the selected theme"""
        try:
            colors = self.get_theme_colors()
            style = ttk.Style()
            self.root.configure(bg=colors['bg'])
            if self.dark_mode:
                style.theme_use('clam')
                style.configure('TLabel',
                              background=colors['bg'],
                              foreground=colors['fg'],
                              font=('Segoe UI', 10))
                style.configure('TFrame',
                              background=colors['bg'],
                              borderwidth=0,
                              relief='flat')
                style.configure('TLabelFrame',
                              background=colors['bg'],
                              foreground=colors['fg'],
                              borderwidth=1,
                              relief='solid',
                              labeloutside=False,
                              font=('Segoe UI', 10, 'bold'))
                style.configure('TNotebook',
                              background=colors['bg'],
                              borderwidth=0,
                              tabmargins=[2, 5, 2, 0])
                style.configure('TNotebook.Tab',
                              background=colors['button_bg'],
                              foreground=colors['fg'],
                              padding=[16, 10],
                              borderwidth=0,
                              font=('Segoe UI', 10))
                style.map('TNotebook.Tab',
                         background=[('selected', colors['bg']), ('active', colors['active'])],
                         foreground=[('selected', colors['select_bg']), ('active', colors['fg'])])
                style.configure('TEntry',
                              fieldbackground=colors['entry_bg'],
                              foreground=colors['entry_fg'],
                              bordercolor=colors['border'],
                              insertcolor=colors['entry_fg'],
                              font=('Segoe UI', 10),
                              borderwidth=2,
                              relief='solid')
                style.map('TEntry',
                         bordercolor=[('focus', colors['select_bg'])],
                         lightcolor=[('focus', colors['select_bg'])],
                         darkcolor=[('focus', colors['select_bg'])])
                style.configure('TButton',
                              background=colors['button_bg'],
                              foreground=colors['button_fg'],
                              borderwidth=0,
                              relief='flat',
                              font=('Segoe UI', 10),
                              padding=[16, 8])
                style.map('TButton',
                         background=[('active', colors['active']), ('pressed', colors['select_bg'])],
                         foreground=[('active', colors['fg']), ('pressed', colors['select_fg'])])
                style.configure('TCheckbutton',
                              background=colors['bg'],
                              foreground=colors['fg'],
                              focuscolor='none',
                              font=('Segoe UI', 10))
                style.map('TCheckbutton',
                         background=[('active', colors['bg'])])
            else:
                if sys.platform == 'win32':
                    style.theme_use('vista')
                else:
                    style.theme_use('clam')
                style.configure('TLabel',
                              background=colors['bg'],
                              foreground=colors['fg'],
                              font=('Segoe UI', 10))
                style.configure('TLabelFrame',
                              font=('Segoe UI', 10, 'bold'),
                              borderwidth=1,
                              relief='solid')
                style.configure('TNotebook.Tab',
                              font=('Segoe UI', 10),
                              padding=[16, 10])
                style.configure('TEntry',
                              font=('Segoe UI', 10),
                              borderwidth=2,
                              relief='solid')
                style.configure('TButton',
                              font=('Segoe UI', 10),
                              padding=[16, 8])
                style.configure('TCheckbutton',
                              font=('Segoe UI', 10))
                self.root.configure(bg=colors['bg'])
            self.update_text_widgets()
        except Exception as e:
            print(f"Theme application error: {e}")
            self.root.configure(bg='#f8f9fa' if not self.dark_mode else '#1a1a1a')
    def update_text_widgets(self):
        """Update text widgets that need manual color configuration"""
        try:
            colors = self.get_theme_colors()
            if hasattr(self, 'chat_canvas'):
                self.chat_canvas.configure(bg=colors['chat_bg'])
            if hasattr(self, 'scrollable_frame'):
                self.scrollable_frame.configure(bg=colors['chat_bg'])
                for widget in self.scrollable_frame.winfo_children():
                    if isinstance(widget, tk.Frame):
                        widget.configure(bg=colors['chat_bg'])
        except Exception as e:
            print(f"Text widget update error: {e}")
    def update_settings_history_display(self):
        """Update the chat history display in settings"""
        for item in self.settings_history_tree.get_children():
            self.settings_history_tree.delete(item)
        for user_id, info in self.chat_history.items():
            is_currently_online = any(device['user_id'] == user_id for device in self.discovered_devices.values())
            status = "🟢 Online" if is_currently_online else "🔴 Offline"
            try:
                if isinstance(info['last_seen'], (int, float)):
                    last_seen = datetime.fromtimestamp(info['last_seen']).strftime("%m/%d %H:%M")
                else:
                    last_seen_dt = datetime.fromisoformat(info['last_seen'].replace('Z', '+00:00'))
                    last_seen = last_seen_dt.strftime("%m/%d %H:%M")
            except (ValueError, KeyError):
                last_seen = "Unknown"
            self.settings_history_tree.insert('', 'end', values=(
                info.get('display_name', 'Unknown'),
                status,
                last_seen
            ))
        chat_count = len(self.chat_history)
        self.chat_count_label.config(text=f"📊 Total conversations: {chat_count}")
    def delete_all_chats(self):
        """Delete all chat history with confirmation"""
        confirm_window = tk.Toplevel(self.root)
        confirm_window.title("⚠️ Confirm Deletion")
        confirm_window.geometry("400x200")
        confirm_window.resizable(False, False)
        confirm_window.transient(self.root)
        confirm_window.grab_set()
        confirm_window.geometry("+%d+%d" % (
            self.root.winfo_rootx() + 50,
            self.root.winfo_rooty() + 50
        ))
        main_frame = ttk.Frame(confirm_window, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        warning_label = ttk.Label(main_frame, text="⚠️ WARNING",
                                 font=("TkDefaultFont", 14, "bold"),
                                 foreground="red")
        warning_label.pack(pady=(0, 10))
        ttk.Label(main_frame, text="This will permanently delete ALL chat history.",
                 font=("TkDefaultFont", 10)).pack(pady=(0, 5))
        ttk.Label(main_frame, text="This action cannot be undone.",
                 font=("TkDefaultFont", 10)).pack(pady=(0, 15))
        ttk.Label(main_frame, text="Type 'delete all chats' to continue:",
                 font=("TkDefaultFont", 10, "bold")).pack(pady=(0, 5))
        confirm_entry = ttk.Entry(main_frame, width=30, font=("TkDefaultFont", 10))
        confirm_entry.pack(pady=(0, 15))
        confirm_entry.focus()
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        def do_delete():
            if confirm_entry.get().strip().lower() == "delete all chats":
                self.chat_history.clear()
                self.save_chat_history()
                self.update_settings_history_display()
                confirm_window.destroy()
                self.update_status("All chat history deleted")
                messagebox.showinfo("Success", "All chat history has been deleted.")
            else:
                messagebox.showerror("Error", "Please type 'delete all chats' exactly to confirm.")
        ttk.Button(button_frame, text="❌ Cancel",
                  command=confirm_window.destroy).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="🗑️ Delete All",
                  command=do_delete).pack(side=tk.RIGHT)
        confirm_entry.bind('<Return>', lambda e: do_delete())
    def setup_chat_tab(self):
        """Setup the chat interface tab"""
        peer_frame = ttk.LabelFrame(self.chat_frame, text="Connected Peer", padding=5)
        peer_frame.pack(fill=tk.X, padx=15, pady=10)
        
        peer_info_container = ttk.Frame(peer_frame)
        peer_info_container.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.peer_info_label = ttk.Label(peer_info_container, text="Not connected")
        self.peer_info_label.pack(anchor=tk.W)
        
        self.encryption_label = ttk.Label(peer_info_container, text="", foreground='green')
        self.encryption_label.pack(anchor=tk.W)
        
        button_container = ttk.Frame(peer_frame)
        button_container.pack(side=tk.RIGHT)
        
        self.security_button = ttk.Button(button_container, text="🔐 Security", 
                                        command=self.show_security_info, state='disabled')
        self.security_button.pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(button_container, text="Disconnect", command=self.disconnect).pack(side=tk.LEFT)
        messages_frame = ttk.LabelFrame(self.chat_frame, text="Messages", padding=10)
        messages_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 10))
        self.chat_canvas = tk.Canvas(messages_frame, highlightthickness=0)
        self.chat_scrollbar = ttk.Scrollbar(messages_frame, orient="vertical", command=self.chat_canvas.yview)
        self.scrollable_frame = tk.Frame(self.chat_canvas)
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))
        )
        self.chat_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.chat_canvas.configure(yscrollcommand=self.chat_scrollbar.set)
        self.chat_canvas.pack(side="left", fill="both", expand=True)
        self.chat_scrollbar.pack(side="right", fill="y")
        self.chat_canvas.bind("<MouseWheel>", self._on_mousewheel)
        input_frame = ttk.Frame(self.chat_frame)
        input_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        input_container = ttk.Frame(input_frame)
        input_container.pack(fill=tk.X)
        self.message_entry = ttk.Entry(input_container, font=('Segoe UI', 11))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.message_entry.bind('<Return>', self.send_message)
        send_button = ttk.Button(input_container, text="Send", command=self.send_message)
        send_button.pack(side=tk.RIGHT)
        self.message_widgets = []
    def _on_mousewheel(self, event):
        """Handle mousewheel scrolling in chat"""
        self.chat_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    def create_chat_bubble(self, message, is_sent=False, timestamp=None, is_verified=True):
        """Create a modern rounded chat bubble widget like texting apps"""
        colors = self.get_theme_colors()
        bubble_container = tk.Frame(self.scrollable_frame, bg=colors['chat_bg'])
        bubble_container.pack(fill=tk.X, padx=20, pady=8)
        
        if not is_verified and not is_sent:
            warning_frame = tk.Frame(bubble_container, bg=colors['chat_bg'])
            warning_frame.pack(fill=tk.X, pady=(0, 4))
            warning_label = tk.Label(
                warning_frame,
                text="⚠️ UNVERIFIED MESSAGE - This message is not encrypted and may not be secure",
                fg="red" if not self.dark_mode else "#ff6b6b",
                bg=colors['chat_bg'],
                font=('Segoe UI', 9, 'bold'),
                wraplength=400
            )
            warning_label.pack()
        
        if is_sent:
            bubble_main = tk.Frame(bubble_container, bg=colors['chat_bg'])
            bubble_main.pack(side=tk.RIGHT, padx=(100, 0))
            bubble_frame = tk.Frame(bubble_main, bg=colors['sent_bubble'], relief='flat', bd=0)
            bubble_frame.pack()
            text_color = colors['sent_text']
            bubble_bg = colors['sent_bubble']
        else:
            bubble_main = tk.Frame(bubble_container, bg=colors['chat_bg'])
            bubble_main.pack(side=tk.LEFT, padx=(0, 100))
            
            if not is_verified:
                bubble_frame = tk.Frame(bubble_main, bg="#ffebee" if not self.dark_mode else "#4a1a1a", relief='solid', bd=1)
            else:
                bubble_frame = tk.Frame(bubble_main, bg=colors['received_bubble'], relief='flat', bd=0)
            bubble_frame.pack()
            
            if not is_verified:
                text_color = "#c62828" if not self.dark_mode else "#ffcdd2"
                bubble_bg = "#ffebee" if not self.dark_mode else "#4a1a1a"
            else:
                text_color = colors['received_text']
                bubble_bg = colors['received_bubble']
        
        top_round = tk.Frame(bubble_frame, bg=bubble_bg, height=2)
        top_round.pack(fill=tk.X, padx=6)
        
        message_text = message
        if not is_verified and not is_sent:
            message_text = f"🔓 {message}"
        
        message_label = tk.Label(
            bubble_frame,
            text=message_text,
            bg=bubble_bg,
            fg=text_color,
            font=('Segoe UI', 11),
            wraplength=250,
            justify=tk.LEFT,
            padx=18,
            pady=12,
            relief='flat',
            bd=0
        )
        message_label.pack(fill=tk.X)
        bottom_round = tk.Frame(bubble_frame, bg=bubble_bg, height=2)
        bottom_round.pack(fill=tk.X, padx=6)
        if is_sent:
            tail_frame = tk.Frame(bubble_main, bg=colors['chat_bg'], height=4)
            tail_frame.pack(fill=tk.X)
            tail_dot = tk.Frame(tail_frame, bg=bubble_bg, width=8, height=4)
            tail_dot.pack(side=tk.RIGHT, padx=(0, 4))
        else:
            tail_frame = tk.Frame(bubble_main, bg=colors['chat_bg'], height=4)
            tail_frame.pack(fill=tk.X)
            tail_dot = tk.Frame(tail_frame, bg=bubble_bg, width=8, height=4)
            tail_dot.pack(side=tk.LEFT, padx=(4, 0))
        if timestamp and self.show_timestamps:
            time_label = tk.Label(
                bubble_container,
                text=timestamp,
                fg=colors['fg'] if self.dark_mode else '#8e8e93',
                bg=colors['chat_bg'],
                font=('Segoe UI', 9),
                pady=4
            )
            if is_sent:
                time_label.pack(side=tk.RIGHT, padx=(0, 20))
            else:
                time_label.pack(side=tk.LEFT, padx=(20, 0))
        self.message_widgets.append(bubble_container)
        self.update_chat_scroll()
        return bubble_container
    def update_chat_scroll(self):
        """Update chat scroll to show latest messages"""
        self.scrollable_frame.update_idletasks()
        self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))
        self.chat_canvas.yview_moveto(1.0)
    def on_name_change(self, event=None):
        """Handle display name change"""
        new_name = self.name_entry.get().strip()
        if new_name and new_name != self.display_name:
            self.display_name = new_name
            self.save_profile()
            self.restart_discovery()
    def refresh_ip(self):
        """Refresh both local and public IP addresses"""
        self.get_local_ip()
        self.get_public_ip()
        self.ip_label.config(text=self.local_ip)
        self.public_ip_label.config(text=self.public_ip)
        self.update_status(f"IPs refreshed - Local: {self.local_ip}, Public: {self.public_ip}")
    def on_mode_change(self):
        """Handle connection mode change"""
        mode = self.mode_var.get()
        self.discover_frame.pack_forget()
        self.manual_frame.pack_forget()
        if mode == "discover":
            self.discover_frame.pack(fill=tk.BOTH, expand=True)
        elif mode == "manual":
            self.manual_frame.pack(fill=tk.BOTH, expand=True, pady=20)
    def start_network_services(self):
        """Start network discovery and chat server"""
        threading.Thread(target=self.discovery_service, daemon=True).start()
        threading.Thread(target=self.chat_server, daemon=True).start()
        threading.Thread(target=self.discovery_broadcast, daemon=True).start()
        self.update_status("Network services started")
    def discovery_service(self):
        """UDP discovery service to find other Chatterbox instances"""
        try:
            self.discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.discovery_socket.bind(('', self.DISCOVERY_PORT))
            while True:
                try:
                    data, addr = self.discovery_socket.recvfrom(1024)
                    if data.startswith(self.MAGIC_BYTES):
                        message_data = data[len(self.MAGIC_BYTES):]
                        message = json.loads(message_data.decode('utf-8'))
                        if addr[0] != self.local_ip and message.get('display_name') != self.display_name:
                            user_id = self.generate_user_id(addr[0], message.get('display_name', 'Unknown'))
                            device_info = {
                                'display_name': message.get('display_name', 'Unknown'),
                                'user_id': user_id,
                                'ip': addr[0],
                                'chat_port': message.get('chat_port', 41235),
                                'last_seen': time.time()
                            }
                            self.discovered_devices[addr[0]] = device_info
                            self.root.after(0, self.update_devices_list)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.discovery_socket:
                        print(f"Discovery service error: {e}")
                    break
        except Exception as e:
            print(f"Failed to start discovery service: {e}")
    def get_broadcast_addresses(self):
        """Get broadcast addresses for all network interfaces"""
        broadcast_addresses = []
        try:
            hostname = socket.gethostname()
            local_ips = socket.gethostbyname_ex(hostname)[2]
            for ip in local_ips:
                if not ip.startswith('127.'):
                    ip_parts = ip.split('.')
                    if len(ip_parts) == 4:
                        broadcast = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.255"
                        broadcast_addresses.append(broadcast)
            if not broadcast_addresses:
                broadcast_addresses = ['192.168.1.255', '192.168.0.255', '10.0.0.255', '172.16.0.255']
        except Exception as e:
            print(f"Error getting broadcast addresses: {e}")
            broadcast_addresses = ['255.255.255.255', '192.168.1.255', '192.168.0.255']
        return broadcast_addresses
    def generate_user_id(self, ip, display_name):
        """Generate a simple user ID from IP and display name"""
        combined = f"{ip}_{display_name}"
        return hashlib.md5(combined.encode()).hexdigest()[:8]
    def discovery_broadcast(self):
        """Broadcast our presence to the network"""
        while True:
            try:
                if self.discovery_socket and self.display_name:
                    message = {
                        'display_name': self.display_name,
                        'chat_port': self.CHAT_PORT,
                        'timestamp': time.time()
                    }
                    data = self.MAGIC_BYTES + json.dumps(message).encode('utf-8')
                    broadcast_addresses = self.get_broadcast_addresses()
                    for broadcast_addr in broadcast_addresses:
                        try:
                            self.discovery_socket.sendto(data, (broadcast_addr, self.DISCOVERY_PORT))
                        except Exception as e:
                            pass
                time.sleep(3)
            except Exception as e:
                print(f"Discovery broadcast error: {e}")
                break
    def chat_server(self):
        """TCP server for incoming chat connections"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('', self.CHAT_PORT))
            self.server_socket.listen(1)
            while True:
                try:
                    client_socket, addr = self.server_socket.accept()
                    if not self.is_connected:
                        self.peer_socket = client_socket
                        self.is_connected = True
                        threading.Thread(target=self.handle_peer_connection,
                                       args=(client_socket, addr), daemon=True).start()
                        self.root.after(0, lambda: self.on_connection_established(addr))
                    else:
                        client_socket.close()
                except Exception as e:
                    if self.server_socket:
                        print(f"Chat server error: {e}")
                    break
        except Exception as e:
            print(f"Failed to start chat server: {e}")
    def handle_peer_connection(self, peer_socket, addr):
        """Handle incoming messages from peer with secure handshake or plain text fallback"""
        try:
            first_data = peer_socket.recv(4096)
            if not first_data:
                return
            
            is_secure_connection = False
            peer_name = f"User@{addr[0]}"
            
            try:
                message = json.loads(first_data.decode('utf-8'))
                
                if message.get('type') == 'handshake':
                    peer_public_key = message.get('public_key')
                    peer_name = message.get('display_name', 'Unknown')
                    
                    my_public_key = self.secure_chat.generate_dh_keypair()
                    fingerprint = self.secure_chat.compute_shared_secret(peer_public_key)
                    
                    handshake_response = {
                        'type': 'handshake_response',
                        'public_key': my_public_key,
                        'display_name': self.display_name
                    }
                    peer_socket.send(json.dumps(handshake_response).encode('utf-8'))
                    
                    verification_data = peer_socket.recv(1024)
                    verification = json.loads(verification_data.decode('utf-8'))
                    
                    if verification.get('type') == 'verification_accepted':
                        if self.verify_peer_fingerprint(fingerprint, peer_name):
                            is_secure_connection = True
                            self.root.after(0, lambda: self.update_status("🔐 Secure connection established!"))
                        else:
                            peer_socket.close()
                            return
                    else:
                        self.root.after(0, lambda: self.update_status("Connection rejected by peer"))
                        peer_socket.close()
                        return
                else:
                    self.root.after(0, lambda: self.add_message(
                        message.get('sender', peer_name),
                        message.get('text', ''),
                        False,
                        is_verified=False
                    ))
                    
            except (json.JSONDecodeError, UnicodeDecodeError):
                try:
                    plain_text = first_data.decode('utf-8', errors='ignore').strip()
                    if plain_text:
                        self.root.after(0, lambda: self.add_message(
                            peer_name,
                            plain_text,
                            False,
                            is_verified=False
                        ))
                except Exception:
                    pass
            
            user_id = self.generate_user_id(addr[0], peer_name)
            self.peer_info = {
                'display_name': peer_name,
                'user_id': user_id,
                'ip': addr[0],
                'is_verified': is_secure_connection
            }
            self.root.after(0, self.update_peer_info)
            
            if not is_secure_connection:
                self.root.after(0, lambda: self.update_status("⚠️ Unverified connection - messages may not be secure!"))
            
            while self.is_connected:
                data = peer_socket.recv(4096)
                if not data:
                    break
                
                try:
                    if is_secure_connection:
                        message = json.loads(data.decode('utf-8'))
                        if message.get('type') == 'chat':
                            encrypted_text = message.get('text', '')
                            decrypted_text = self.secure_chat.decrypt_message(encrypted_text)
                            self.root.after(0, lambda: self.add_message(
                                message.get('sender', peer_name),
                                decrypted_text,
                                False,
                                is_verified=True
                            ))
                    else:
                        try:
                            message = json.loads(data.decode('utf-8'))
                            text = message.get('text', message.get('message', str(message)))
                            sender = message.get('sender', message.get('from', peer_name))
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            text = data.decode('utf-8', errors='ignore').strip()
                            sender = peer_name
                        
                        if text:
                            self.root.after(0, lambda: self.add_message(
                                sender,
                                text,
                                False,
                                is_verified=False
                            ))
                except Exception as msg_error:
                    print(f"Message handling error: {msg_error}")
                    continue
                
        except Exception as e:
            print(f"Peer connection error: {e}")
        finally:
            self.root.after(0, self.disconnect)
    def update_devices_list(self):
        """Update the discovered devices list"""
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
        current_time = time.time()
        active_devices = {}
        for ip, device in self.discovered_devices.items():
            if current_time - device['last_seen'] < 10:
                active_devices[ip] = device
                self.devices_tree.insert('', 'end', values=(
                    device['display_name'],
                    device['ip']
                ))
        self.discovered_devices = active_devices
        for ip, device in active_devices.items():
            self.update_peer_status(device['user_id'], True)
        if hasattr(self, 'settings_history_tree'):
            self.update_settings_history_display()
    def refresh_discovery(self):
        """Refresh device discovery"""
        self.discovered_devices.clear()
        self.update_devices_list()
        self.update_status("Refreshing device discovery...")
    def restart_discovery(self):
        """Restart discovery with new profile info"""
        self.update_status("Updated profile information")
    def on_device_select(self, event):
        """Handle device selection from list"""
        selection = self.devices_tree.selection()
        if selection:
            item = self.devices_tree.item(selection[0])
            values = item['values']
            if values:
                ip = values[1]
                self.connect_to_ip(ip)
    def connect_manual_ip(self):
        """Connect using manual IP entry"""
        ip = self.ip_entry.get().strip()
        if ip:
            self.connect_to_ip(ip)
        else:
            messagebox.showerror("Error", "Please enter an IP address")
    def verify_peer_fingerprint(self, fingerprint, peer_name):
        verify_window = tk.Toplevel(self.root)
        verify_window.title("🔐 Verify Peer Identity")
        verify_window.geometry("500x300")
        verify_window.resizable(False, False)
        verify_window.grab_set()
        
        main_frame = ttk.Frame(verify_window, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        title_label = ttk.Label(main_frame, text="🔐 Secure Connection Established", 
                              font=('Segoe UI', 14, 'bold'))
        title_label.pack(pady=(0, 15))
        
        info_label = ttk.Label(main_frame, 
                              text=f"Please verify the identity of '{peer_name}' by confirming\nthe security fingerprint matches on both devices:",
                              justify=tk.CENTER)
        info_label.pack(pady=(0, 15))
        
        fingerprint_frame = ttk.LabelFrame(main_frame, text="Security Fingerprint", padding=15)
        fingerprint_frame.pack(fill=tk.X, pady=(0, 20))
        
        fingerprint_label = ttk.Label(fingerprint_frame, text=fingerprint, 
                                    font=('Courier New', 16, 'bold'),
                                    foreground='blue')
        fingerprint_label.pack()
        
        warning_label = ttk.Label(main_frame,
                                text="⚠️ Only accept if this fingerprint matches exactly!\nIf it doesn't match, someone may be intercepting your connection.",
                                justify=tk.CENTER,
                                foreground='red')
        warning_label.pack(pady=(0, 20))
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack()
        
        result = {'verified': False}
        
        def accept():
            result['verified'] = True
            verify_window.destroy()
            
        def reject():
            result['verified'] = False
            verify_window.destroy()
        
        ttk.Button(button_frame, text="✅ Accept & Connect", command=accept).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="❌ Reject & Disconnect", command=reject).pack(side=tk.LEFT)
        
        verify_window.wait_window()
        return result['verified']

    def show_encryption_status(self, fingerprint):
        status_window = tk.Toplevel(self.root)
        status_window.title("🔐 Connection Security")
        status_window.geometry("400x200")
        status_window.resizable(False, False)
        
        main_frame = ttk.Frame(status_window, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="🔐 Secure Connection Active", 
                 font=('Segoe UI', 14, 'bold'), foreground='green').pack(pady=(0, 10))
        
        ttk.Label(main_frame, text="Your messages are encrypted with AES-256").pack(pady=(0, 10))
        
        ttk.Label(main_frame, text=f"Session Fingerprint: {fingerprint}", 
                 font=('Courier New', 10)).pack(pady=(0, 15))
        
        ttk.Button(main_frame, text="Close", command=status_window.destroy).pack()

    def connect_to_ip(self, ip):
        """Connect to a specific IP address with fallback to plain text"""
        if self.is_connected:
            messagebox.showwarning("Warning", "Already connected to a peer")
            return
        if ip == self.local_ip or ip == self.public_ip or ip == "127.0.0.1" or ip == "localhost":
            messagebox.showerror("Error", "Cannot connect to yourself!")
            return
        try:
            self.update_status(f"Connecting to {ip}...")
            chat_port = self.CHAT_PORT
            if ip in self.discovered_devices:
                chat_port = self.discovered_devices[ip].get('chat_port', self.CHAT_PORT)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((ip, chat_port))
            
            is_secure_connection = False
            peer_name = f"User@{ip}"
            
            try:
                self.update_status("Attempting secure handshake...")
                my_public_key = self.secure_chat.generate_dh_keypair()
                
                handshake_message = {
                    'type': 'handshake',
                    'public_key': my_public_key,
                    'display_name': self.display_name
                }
                sock.send(json.dumps(handshake_message).encode('utf-8'))
                
                response_data = sock.recv(4096)
                response = json.loads(response_data.decode('utf-8'))
                
                if response.get('type') == 'handshake_response':
                    peer_public_key = response.get('public_key')
                    peer_name = response.get('display_name', 'Unknown')
                    
                    fingerprint = self.secure_chat.compute_shared_secret(peer_public_key)
                    
                    if self.verify_peer_fingerprint(fingerprint, peer_name):
                        is_secure_connection = True
                        self.update_status("🔐 Secure connection established!")
                        
                        verification_message = {'type': 'verification_accepted'}
                        sock.send(json.dumps(verification_message).encode('utf-8'))
                    else:
                        self.update_status("Connection rejected by user")
                        verification_message = {'type': 'verification_rejected'}
                        sock.send(json.dumps(verification_message).encode('utf-8'))
                        sock.close()
                        return
                else:
                    raise Exception("Invalid handshake response")
                    
            except Exception as secure_error:
                print(f"Secure handshake failed, falling back to plain text: {secure_error}")
                sock.close()
                
                # Ask user if they want to proceed with unverified connection
                proceed = messagebox.askyesno(
                    "⚠️ Security Warning", 
                    f"Could not establish secure connection with {ip}.\n\n"
                    f"The peer may be using a different chat application or protocol.\n"
                    f"Your messages will NOT be encrypted and may be visible to others.\n\n"
                    f"Do you want to proceed with an unverified connection?",
                    icon="warning"
                )
                
                if not proceed:
                    self.update_status("Connection cancelled by user")
                    return
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((ip, chat_port))
                
                self.update_status("⚠️ Connected without encryption - messages are not secure!")
                
                hello_message = f"Hello from {self.display_name}"
                sock.send(hello_message.encode('utf-8'))
                
                is_secure_connection = False
            
            self.peer_socket = sock
            self.is_connected = True
            
            if ip in self.discovered_devices:
                device = self.discovered_devices[ip]
                self.peer_info = {
                    'display_name': device['display_name'],
                    'user_id': device['user_id'],
                    'ip': ip,
                    'port': device.get('chat_port', self.CHAT_PORT),
                    'is_verified': is_secure_connection
                }
            else:
                user_id = self.generate_user_id(ip, peer_name)
                self.peer_info = {
                    'display_name': peer_name,
                    'user_id': user_id,
                    'ip': ip,
                    'port': chat_port,
                    'is_verified': is_secure_connection
                }
            
            threading.Thread(target=self.handle_peer_connection,
                           args=(sock, (ip, self.CHAT_PORT)), daemon=True).start()
            self.on_connection_established((ip, self.CHAT_PORT))
            
            if self.peer_info:
                self.update_peer_status(self.peer_info['user_id'], True)
                if self.peer_info['user_id'] in self.chat_history:
                    self.chat_history[self.peer_info['user_id']]['display_name'] = self.peer_info['display_name']
                    self.chat_history[self.peer_info['user_id']]['message_count'] += 1
                    self.save_chat_history()
                    
        except ConnectionRefusedError:
            self.update_status("Connection failed")
            messagebox.showerror("Connection Error", f"Connection refused by {ip}. Make sure a chat app is running on that device.")
        except socket.timeout:
            self.update_status("Connection failed")
            messagebox.showerror("Connection Error", f"Connection to {ip} timed out. Check the IP address and network connection.")
        except Exception as e:
            self.update_status("Connection failed")
            messagebox.showerror("Connection Error", f"Failed to connect to {ip}: {str(e)}")
    def on_connection_established(self, addr):
        """Handle successful connection"""
        self.notebook.tab(1, state="normal")
        self.notebook.select(1)
        self.update_peer_info()
        self.update_status(f"Connected to {addr[0]}")
        self.message_entry.focus()
    def show_security_info(self):
        """Show security information dialog"""
        if self.secure_chat.is_encrypted:
            fingerprint = self.secure_chat.get_key_fingerprint()
            self.show_encryption_status(fingerprint)

    def update_peer_info(self):
        """Update peer information display"""
        if self.peer_info:
            info_text = f"{self.peer_info['display_name']} - {self.peer_info['ip']}"
            self.peer_info_label.config(text=info_text)
            
            is_verified = self.peer_info.get('is_verified', False)
            
            if is_verified and self.secure_chat.is_encrypted:
                self.encryption_label.config(text="🔐 End-to-End Encrypted", foreground="green")
                self.security_button.config(state='normal')
            else:
                self.encryption_label.config(text="⚠️ UNVERIFIED - Not Encrypted", foreground="red")
                self.security_button.config(state='disabled')
    def send_message(self, event=None):
        """Send a message to the peer"""
        if not self.is_connected or not self.peer_socket:
            return
        text = self.message_entry.get().strip()
        if not text:
            return
        try:
            is_verified = self.peer_info.get('is_verified', False) if self.peer_info else False
            
            if is_verified and self.secure_chat.is_encrypted:
                encrypted_text = self.secure_chat.encrypt_message(text)
                message = {
                    'type': 'chat',
                    'sender': self.display_name,
                    'text': encrypted_text,
                    'timestamp': time.time()
                }
                self.peer_socket.send(json.dumps(message).encode('utf-8'))
            else:
                try:
                    message = {
                        'sender': self.display_name,
                        'text': text,
                        'timestamp': time.time()
                    }
                    self.peer_socket.send(json.dumps(message).encode('utf-8'))
                except:
                    self.peer_socket.send(text.encode('utf-8'))
            
            self.add_message(self.display_name, text, True, is_verified=is_verified)
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            self.update_status("Failed to send message")
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")
    def add_message(self, sender, text, is_own, is_verified=True):
        """Add a message to the chat display using modern bubbles"""
        timestamp = datetime.now().strftime("%H:%M") if self.show_timestamps else None
        self.create_chat_bubble(text, is_sent=is_own, timestamp=timestamp, is_verified=is_verified)
        if self.peer_info:
            peer_key = f"{self.peer_info['ip']}:{self.peer_info['port']}"
            if peer_key not in self.chat_history:
                self.chat_history[peer_key] = {
                    'name': sender if not is_own else self.display_name,
                    'messages': [],
                    'last_seen': datetime.now().isoformat(),
                    'online': True
                }
            self.chat_history[peer_key]['messages'].append({
                'sender': "You" if is_own else sender,
                'text': text,
                'timestamp': datetime.now().isoformat(),
                'is_own': is_own,
                'is_verified': is_verified
            })
            self.save_chat_history()
    def disconnect(self):
        """Disconnect from peer"""
        self.is_connected = False
        if self.peer_socket:
            try:
                self.peer_socket.close()
            except:
                pass
            self.peer_socket = None
        self.peer_info = None
        
        self.secure_chat = SecureChat()
        
        self.peer_info_label.config(text="Not connected")
        self.encryption_label.config(text="")
        self.security_button.config(state='disabled')
        
        self.notebook.tab(1, state="disabled")
        self.notebook.select(0)
        for widget in self.message_widgets:
            widget.destroy()
        self.message_widgets.clear()
        self.update_chat_scroll()
        self.update_status("Disconnected")
    def update_status(self, message):
        """Update status bar"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status_bar.config(text=f"[{timestamp}] {message} | Local IP: {self.local_ip} | Public IP: {self.public_ip}")
    def on_closing(self):
        """Handle application closing"""
        self.is_connected = False
        if self.peer_socket:
            try:
                self.peer_socket.close()
            except:
                pass
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        if self.discovery_socket:
            try:
                self.discovery_socket.close()
            except:
                pass
        self.root.destroy()
    def run(self):
        """Start the application"""
        self.root.mainloop()
if __name__ == "__main__":
    app = ChatterboxApp()
    app.run()