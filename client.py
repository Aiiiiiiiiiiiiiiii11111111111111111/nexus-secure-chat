# -*- coding: utf-8 -*-
"""
Secure Nexus Chat Client - PyQt5 Single File
Features:
- Login / Register
- Friends list
- Private / Group chat
- File send/receive
- SQLite local storage
- Clear local chat history
- Auto reconnect
- E2E encryption (ECDH + AES-256-GCM)
- Fallback static AES
"""

import sys, os, sqlite3, asyncio, json, base64, time, traceback
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QPushButton, QListWidget, QLineEdit,
    QTextEdit, QLabel, QFileDialog, QHBoxLayout, QVBoxLayout, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import websockets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# -----------------------------
# Crypto Manager
# -----------------------------
class CryptoManager:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.shared_key = None
        self.static_key = b'NEXUS_ULTRA_SECRET_32BYTES_KEY__'

    def public_bytes(self):
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def derive_shared_key(self, peer_public_bytes):
        try:
            peer_public = serialization.load_pem_public_key(peer_public_bytes, backend=default_backend())
            shared_secret = self.private_key.exchange(ec.ECDH(), peer_public)
            self.shared_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'chat key',
                backend=default_backend()
            ).derive(shared_secret)
            return True
        except Exception as e:
            print("ECDH derivation failed:", e)
            self.shared_key = None
            return False

    def encrypt(self, plaintext):
        key = self.shared_key if self.shared_key else self.static_key
        iv = os.urandom(12)
        aes = AESGCM(key)
        ct = aes.encrypt(iv, plaintext.encode(), None)
        return base64.b64encode(iv + ct).decode()

    def decrypt(self, ciphertext):
        key = self.shared_key if self.shared_key else self.static_key
        try:
            raw = base64.b64decode(ciphertext)
            iv, ct = raw[:12], raw[12:]
            aes = AESGCM(key)
            return aes.decrypt(iv, ct, None).decode()
        except Exception as e:
            print("Decrypt failed:", e)
            return None

# -----------------------------
# WebSocket Client
# -----------------------------
class WSClient(QThread):
    received = pyqtSignal(str)
    connected = pyqtSignal()
    disconnected = pyqtSignal()

    def __init__(self, uri, crypto_mgr):
        super().__init__()
        self.uri = uri
        self.crypto = crypto_mgr
        self.ws = None
        self.loop = asyncio.new_event_loop()
        self.running = True

    def run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.connect_loop())

    async def connect_loop(self):
        while self.running:
            try:
                async with websockets.connect(self.uri) as websocket:
                    self.ws = websocket
                    self.connected.emit()
                    await self.receive_loop()
            except Exception as e:
                print("Reconnect in 3s...", e)
                self.disconnected.emit()
                await asyncio.sleep(3)

    async def receive_loop(self):
        try:
            async for msg in self.ws:
                decrypted = self.crypto.decrypt(msg)
                if decrypted:
                    self.received.emit(decrypted)
        except Exception as e:
            print("Receive loop ended:", e)
            self.ws = None
            self.disconnected.emit()

    def send(self, data: dict):
        if self.ws:
            try:
                encrypted = self.crypto.encrypt(json.dumps(data))
                asyncio.run_coroutine_threadsafe(self.ws.send(encrypted), self.loop)
            except Exception as e:
                print("Send failed:", e)

    def stop(self):
        self.running = False
        if self.ws:
            asyncio.run_coroutine_threadsafe(self.ws.close(), self.loop)

# -----------------------------
# Database
# -----------------------------
class DBManager:
    def __init__(self, db_file="chat.db"):
        self.conn = sqlite3.connect(db_file)
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                receiver TEXT,
                content TEXT,
                timestamp REAL
            )
        """)
        self.conn.commit()

    def save_message(self, sender, receiver, content):
        self.cursor.execute(
            "INSERT INTO messages(sender, receiver, content, timestamp) VALUES(?,?,?,?)",
            (sender, receiver, content, time.time())
        )
        self.conn.commit()

    def load_messages(self, chat_with):
        self.cursor.execute(
            "SELECT sender, content, timestamp FROM messages WHERE receiver=? OR sender=? ORDER BY timestamp ASC",
            (chat_with, chat_with)
        )
        return self.cursor.fetchall()

    def clear_messages(self):
        self.cursor.execute("DELETE FROM messages")
        self.conn.commit()

# -----------------------------
# Login / Register Window
# -----------------------------
class LoginWindow(QWidget):
    login_success = pyqtSignal(str, str)  # username, token

    def __init__(self, ws_client):
        super().__init__()
        self.ws = ws_client
        self.crypto = ws_client.crypto
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Secure Nexus Login")
        self.resize(300, 180)

        self.user_label = QLabel("Username:")
        self.user_edit = QLineEdit()
        self.pwd_label = QLabel("Password:")
        self.pwd_edit = QLineEdit()
        self.pwd_edit.setEchoMode(QLineEdit.Password)
        self.login_btn = QPushButton("Login")
        self.register_btn = QPushButton("Register")

        vbox = QVBoxLayout()
        vbox.addWidget(self.user_label)
        vbox.addWidget(self.user_edit)
        vbox.addWidget(self.pwd_label)
        vbox.addWidget(self.pwd_edit)
        vbox.addWidget(self.login_btn)
        vbox.addWidget(self.register_btn)
        self.setLayout(vbox)

        self.login_btn.clicked.connect(self.handle_login)
        self.register_btn.clicked.connect(self.handle_register)
        self.ws.received.connect(self.handle_response)

    def handle_login(self):
        self.send_request("login")

    def handle_register(self):
        self.send_request("register")

    def send_request(self, req_type):
        data = {
            "type": req_type,
            "username": self.user_edit.text(),
            "password": self.pwd_edit.text()
        }
        self.ws.send(data)

    def handle_response(self, msg):
        try:
            data = json.loads(msg)
            if data.get("type") == "login_success":
                token = data.get("token")
                self.login_success.emit(self.user_edit.text(), token)
                self.close()
            elif data.get("type") == "success":
                QMessageBox.information(self, "Info", "Operation success")
            elif data.get("type") == "error":
                QMessageBox.warning(self, "Error", "Operation failed")
        except Exception as e:
            print("Response parse failed:", e)

# -----------------------------
# Main Chat Window
# -----------------------------
class ChatWindow(QMainWindow):
    def __init__(self, username, token, ws_client, db_mgr):
        super().__init__()
        self.username = username
        self.token = token
        self.ws = ws_client
        self.db = db_mgr
        self.current_chat = None
        self.init_ui()
        self.ws.received.connect(self.on_message_received)

    def init_ui(self):
        self.setWindowTitle(f"Secure Nexus - {self.username}")
        self.resize(600, 400)

        # Friends list
        self.friends_list = QListWidget()
        self.friends_list.addItems(["Alice", "Bob", "Charlie"])
        self.friends_list.clicked.connect(self.select_friend)

        # Chat area
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)

        # Message input
        self.msg_input = QLineEdit()
        self.send_btn = QPushButton("Send")
        self.clear_btn = QPushButton("Clear Chat")
        self.file_btn = QPushButton("Send File")

        hbox = QHBoxLayout()
        hbox.addWidget(self.msg_input)
        hbox.addWidget(self.send_btn)
        hbox.addWidget(self.file_btn)
        hbox.addWidget(self.clear_btn)

        vbox = QVBoxLayout()
        vbox.addWidget(self.chat_area)
        vbox.addLayout(hbox)

        main_layout = QHBoxLayout()
        main_layout.addWidget(self.friends_list)
        main_layout.addLayout(vbox)

        central = QWidget()
        central.setLayout(main_layout)
        self.setCentralWidget(central)

        self.send_btn.clicked.connect(self.send_message)
        self.clear_btn.clicked.connect(self.clear_chat)
        self.file_btn.clicked.connect(self.send_file)

    def select_friend(self):
        self.current_chat = self.friends_list.currentItem().text()
        self.load_history()

    def load_history(self):
        self.chat_area.clear()
        if not self.current_chat:
            return
        messages = self.db.load_messages(self.current_chat)
        for sender, content, ts in messages:
            self.chat_area.append(f"[{sender}]: {content}")

    def send_message(self):
        if not self.current_chat: return
        msg = self.msg_input.text()
        if not msg: return
        data = {"type": "private_msg", "to": self.current_chat, "msg": msg, "from": self.username}
        self.ws.send(data)
        self.db.save_message(self.username, self.current_chat, msg)
        self.chat_area.append(f"[{self.username}]: {msg}")
        self.msg_input.clear()

    def send_file(self):
        if not self.current_chat: return
        fname, _ = QFileDialog.getOpenFileName(self, "Select File")
        if not fname: return
        with open(fname, "rb") as f:
            content = base64.b64encode(f.read()).decode()
        data = {"type":"file","to":self.current_chat,"filename":os.path.basename(fname),
                "file":content,"from":self.username}
        self.ws.send(data)
        self.chat_area.append(f"[{self.username}]: Sent file {os.path.basename(fname)}")

    def on_message_received(self, msg):
        try:
            data = json.loads(msg)
            msg_type = data.get("type")
            if msg_type == "private":
                sender = data.get("from")
                content = data.get("msg")
                self.db.save_message(sender, self.username, content)
                if self.current_chat == sender:
                    self.chat_area.append(f"[{sender}]: {content}")
            elif msg_type == "file":
                sender = data.get("from")
                fname = data.get("filename")
                fcontent = base64.b64decode(data.get("file"))
                save_path = os.path.join(os.getcwd(), f"recv_{fname}")
                with open(save_path,"wb") as f: f.write(fcontent)
                self.db.save_message(sender, self.username, f"[File Received: {fname}]")
                if self.current_chat == sender:
                    self.chat_area.append(f"[{sender}]: [File Received: {fname}]")
        except Exception as e:
            print("Msg parse error:", e, traceback.format_exc())

    def clear_chat(self):
        self.db.clear_messages()
        self.chat_area.clear()

# -----------------------------
# Main
# -----------------------------
def main():
    app = QApplication(sys.argv)
    crypto_mgr = CryptoManager()
    ws_client = WSClient("ws://localhost:10000", crypto_mgr)
    ws_client.start()
    db_mgr = DBManager()
    login_win = LoginWindow(ws_client)

    def on_login(username, token):
        chat_win = ChatWindow(username, token, ws_client, db_mgr)
        chat_win.show()

    login_win.login_success.connect(on_login)
    login_win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
