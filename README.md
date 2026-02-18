# Secure Nexus Chat

## Overview
Secure QQ-style chat system with PyQt5 client and Node.js server.
Features:
- Login/Register
- Friends list
- Private/Group chat
- File transfer
- SQLite local storage
- Clear chat history
- Auto reconnect
- E2E encryption (ECDH + AES-GCM)

## Setup Server
```bash
cd server
npm install
node server.js
