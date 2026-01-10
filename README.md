# 🔐 Wanna Chat - Secure End-to-End Encrypted Chat Application

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-AES--256--GCM-brightgreen.svg)](SECURITY.md)
[![Status](https://img.shields.io/badge/status-active-success.svg)]()

A secure peer-to-peer chat application implementing modern cryptographic protocols including mutual authentication, Diffie-Hellman key exchange, AES-256-GCM encryption, and digital signatures.

## ✨ Features

### 🛡️ Security Features
- **Mutual Authentication**: X.509 certificate-based authentication with RSA-4096
- **Key Exchange**: Diffie-Hellman (3072-bit) for secure session key establishment
- **Encryption**: AES-256-GCM for authenticated encryption (confidentiality + integrity)
- **Message Integrity**: Dual-layer protection (GCM authentication tag + HMAC-SHA256)
- **Digital Signatures**: RSA-4096 with PSS padding for message authenticity
- **Replay Protection**: Sequence number validation to prevent replay attacks
- **Encrypted Logging**: All chat logs encrypted with AES-256-GCM
- **Perfect Forward Secrecy**: Ephemeral DH keys ensure past messages stay secure

### 💬 Application Features
- Modern, user-friendly GUI with dark theme
- Persistent chat history across sessions
- Real-time message delivery with typing indicators
- Connection status indicators with visual feedback
- Server/Client mode support
- Automatic reconnection handling
- Batch history writes for performance

### 🔬 Security Testing Tools
- **Attack Testing Tool**: Built-in MITM proxy for security validation
  - Replay attack simulation (sequence number validation)
  - Message tampering detection (HMAC/GCM verification)
  - Message dropping (packet loss simulation)
  - Delay attack testing (timing resistance)
  - Certificate substitution testing (signature verification)

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager
- tkinter (usually included with Python)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/wanna-chat.git
cd wanna-chat
```

2. Install dependencies:
```bash
pip install cryptography
```

Or use requirements.txt:
```bash
pip install -r requirements.txt
```

### Running the Application

#### Start as Server:
```bash
python main.py
```
- Select "Server" role
- Enter username
- Set port (default: 5000)
- Click "Connect"
- Wait for client connection

#### Start as Client:
```bash
python main.py
```
- Select "Client" role
- Enter username
- Enter server IP address (e.g., 127.0.0.1 for local)
- Set port (must match server, default: 5000)
- Click "Connect"

### Testing Security Features

Run the attack testing tool:
```bash
python attack_tool.py
```

**Testing Setup:**
1. Start chat server on a different port (e.g., 5555 instead of 5000)
2. Start attack tool proxy listening on port 5000, forwarding to 127.0.0.1:5555
3. Client connects to port 5000 (gets intercepted by proxy)
4. Use the attack tool buttons to simulate various attacks

**Expected Results:**
- ✅ MITM interception succeeds but messages remain encrypted
- ✅ Replay attacks detected and rejected
- ✅ Tampered messages fail integrity checks
- ✅ Certificate substitution prevented by signature verification

## 🗝️ Architecture

### Cryptographic Protocol Flow

```
1. TCP Connection Established
   ↓
2. Certificate Exchange (Mutual Authentication)
   - Both parties exchange X.509 certificates
   - Certificates contain RSA-4096 public keys
   - Peer identities verified via certificate CN
   ↓
3. Diffie-Hellman Key Exchange (Perfect Forward Secrecy)
   - Server generates 3072-bit DH parameters
   - Parameters signed with RSA-4096 private key
   - Client verifies signature with server's public key
   - Both parties exchange signed DH public keys
   - Shared secret computed independently
   ↓
4. Session Key Derivation (PBKDF2-HMAC-SHA256)
   - 100,000 iterations for key stretching
   - Derives 64 bytes of key material:
     * First 32 bytes: AES-256 encryption key
     * Last 32 bytes: HMAC-SHA256 key
   ↓
5. Secure Communication
   - Messages encrypted with AES-256-GCM
   - GCM provides authenticated encryption
   - HMAC-SHA256 adds second integrity layer
   - RSA-PSS signatures for non-repudiation
   - Sequence numbers prevent replay attacks
```

### Message Format

**JSON Structure (before encryption):**
```json
{
  "seq": 0,
  "text": "Hello, World!",
  "sender": "Alice",
  "timestamp": "2025-01-10T12:00:00Z",
  "signed": true,
  "signature": "base64_encoded_rsa_pss_signature"
}
```

**Wire Protocol (transmitted bytes):**
```
[4 bytes: total length]
[32 bytes: HMAC-SHA256]
[12 bytes: AES-GCM IV]
[16 bytes: GCM authentication tag]
[variable bytes: AES-256-GCM encrypted JSON]
```

**Security Layers:**
1. **Outer Layer**: HMAC-SHA256 (detects tampering before decryption)
2. **Middle Layer**: AES-256-GCM (authenticated encryption)
3. **Inner Layer**: RSA-PSS signature (proves sender identity)
4. **Replay Protection**: Sequence number (prevents message reuse)

## 📁 Project Structure

```
wanna-chat/
├── main.py                 # Application entry point
├── gui.py                  # Modern GUI implementation (Tkinter)
├── secure_base.py          # Core cryptographic functionality
├── secure_server.py        # Server implementation (listens for connections)
├── secure_client.py        # Client implementation (connects to server)
├── config.py               # Configuration management
├── attack_tool.py          # Security testing tool (MITM proxy)
├── test_reqs.py            # Requirements verification script
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── __init__.py            # Python package marker
└── chat_history/          # Persistent chat storage (auto-created)
    └── alice_bob_history.json
```

## 🔒 Security Specifications

### Algorithms Used

| Component | Algorithm | Key Size | Mode/Padding |
|-----------|-----------|----------|--------------|
| Asymmetric Encryption | RSA | 4096 bits | OAEP-SHA256 |
| Key Exchange | Diffie-Hellman | 3072 bits | RFC 3526 Group |
| Symmetric Encryption | AES | 256 bits | GCM (Galois/Counter Mode) |
| Message Integrity | HMAC | 256 bits | SHA-256 |
| Digital Signature | RSA | 4096 bits | PSS-SHA256 |
| Key Derivation | PBKDF2 | 64 bytes output | HMAC-SHA256, 100k iterations |
| Hash Function | SHA-256 | 256 bits | - |

### Security Properties

✅ **Confidentiality**: AES-256-GCM encryption protects message content  
✅ **Integrity**: Triple-layer verification (GCM tag + HMAC + RSA signature)  
✅ **Authenticity**: RSA-4096 signatures verify sender identity  
✅ **Forward Secrecy**: Ephemeral DH keys provide session-specific encryption  
✅ **Replay Protection**: Sequence numbers prevent message replay attacks  
✅ **Non-Repudiation**: Digital signatures provide cryptographic proof of origin  
✅ **Authentication**: Mutual X.509 certificate verification  
✅ **Key Derivation**: PBKDF2 with 100,000 iterations resists brute force  

### Threat Model

**Protected Against:**
- ✅ Eavesdropping (passive network monitoring)
- ✅ Man-in-the-middle attacks (certificate verification)
- ✅ Replay attacks (sequence number validation)
- ✅ Message tampering (HMAC + GCM authentication)
- ✅ Message forgery (RSA signatures)
- ✅ Certificate substitution (signature verification)
- ✅ Brute force (strong key sizes: RSA-4096, AES-256, DH-3072)

**Not Protected Against:**
- ❌ Endpoint compromise (malware on user's computer)
- ❌ Social engineering attacks
- ❌ Side-channel attacks (timing, power analysis)
- ❌ Quantum computers (RSA/DH vulnerable to Shor's algorithm)

## 🧪 Testing

### Run Requirement Verification
```bash
python test_reqs.py
```

This checks:
- ✓ All required files exist
- ✓ Dependencies are installed correctly
- ✓ Security features are implemented
- ✓ Message format is correct
- ✓ Replay protection works
- ✓ Signature verification functions
- ✓ Encryption strength (RSA-4096, DH-3072, AES-256)

### Manual Security Testing

1. **Normal Operation Test**:
   ```bash
   # Terminal 1
   python main.py  # Start as server, port 5000
   
   # Terminal 2
   python main.py  # Start as client, connect to 127.0.0.1:5000
   ```
   - Exchange messages
   - Verify encryption/decryption works
   - Check chat history persistence

2. **Replay Attack Test**:
   ```bash
   # Terminal 1: Server on port 5555
   python main.py  # Server, port 5555
   
   # Terminal 2: Attack tool proxy
   python attack_tool.py  # Listen 5000 -> Forward 5555
   
   # Terminal 3: Client connects to proxy
   python main.py  # Client, connect to 127.0.0.1:5000
   ```
   - Send a message
   - Select the message in attack tool
   - Click "Replay Attack"
   - Verify "⚠️ REPLAY ATTACK DETECTED!" appears

3. **Tampering Test**:
   - Use same setup as replay test
   - Click "Message Tampering" in attack tool
   - Verify message rejected with "HMAC VERIFICATION FAILED" or decryption error

4. **Man-in-the-Middle Test**:
   - Position attack tool between client/server
   - Observe intercepted messages in attack tool
   - Verify content remains encrypted in attack log
   - Confirm messages still readable in chat windows

## 📊 Performance

### Handshake Performance
- **RSA-4096 key generation**: ~500ms per party
- **DH-3072 parameter generation**: ~1-2 seconds (server only)
- **Certificate exchange**: <100ms
- **DH public key exchange**: ~200ms
- **Total handshake time**: ~2-3 seconds

### Message Performance
- **Encryption (AES-256-GCM)**: <1ms per message
- **HMAC computation**: <0.5ms
- **Signature generation (RSA-4096)**: ~5-10ms
- **Signature verification**: ~1-2ms
- **Total overhead**: ~6-13ms per message
- **Network latency**: Depends on connection (local: <1ms, internet: 20-200ms)

### Optimizations Implemented
- Hardware-accelerated AES-GCM (via cryptography library)
- Batch history writes (reduces disk I/O)
- Threaded message handling (non-blocking GUI)
- Cached chat history (loads once per session)
- Reused TCP connection (no reconnection overhead)

## 📝 Configuration

### Port Configuration
Default port is 5000. To use a different port:
```python
# In gui.py, change default port
self.port_entry.insert(0, "5000")  # Change this value
```

### Cryptographic Parameters
Adjust in `secure_base.py`:

```python
# RSA key size (2048, 3072, 4096, 8192)
key_size=4096

# DH key size (2048, 3072, 4096)
key_size=3072

# PBKDF2 iterations (higher = slower but more secure)
iterations=100000
```

### GUI Customization
Colors defined in `gui.py`:
```python
self.colors = {
    'bg': '#1e1e2e',           # Background
    'accent': '#89b4fa',        # Accent color
    'success': '#a6e3a1',       # Success messages
    'error': '#f38ba8',         # Error messages
    # ... modify as needed
}
```

## 🤝 Contributing

Contributions welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`python test_reqs.py`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Coding Standards
- Follow PEP 8 style guide
- Add docstrings to all functions
- Never weaken cryptographic security
- Test security features thoroughly
- Update documentation for new features

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Security Disclaimer

**Educational Purpose**: This application demonstrates secure communication protocols using industry-standard cryptographic algorithms. While it implements strong security measures, it has not undergone professional security audit.

**For Production Use, Consider:**
- Professional security audit by certified experts
- Proper certificate authority (CA) infrastructure
- Certificate revocation checking (CRL/OCSP)
- Key rotation policies and HSM integration
- Enhanced error handling and logging
- Rate limiting and DoS protection
- User authentication and authorization system
- Compliance with regulations (GDPR, HIPAA, etc.)

**Use at Your Own Risk**: The authors are not responsible for any security breaches or data loss resulting from the use of this software.

## 👥 Authors

- **Your Name** - *Initial work and modern security implementation*

## 🎓 Academic Context

This project demonstrates practical implementation of cryptographic concepts including:
- Public Key Infrastructure (PKI)
- Symmetric and Asymmetric Cryptography
- Key Exchange Protocols
- Message Authentication Codes
- Digital Signatures
- Secure Communication Protocols

**Learning Objectives Achieved:**
- ✓ Understanding of end-to-end encryption
- ✓ Implementation of authenticated encryption
- ✓ Practical experience with cryptographic libraries
- ✓ Security testing and vulnerability analysis
- ✓ Network programming and protocol design

## 🙏 Acknowledgments

- **Cryptography Library**: Built with the excellent [cryptography](https://cryptography.io/) library
- **Protocol Inspiration**: Concepts from TLS 1.3, Signal Protocol, and PGP
- **Security Research**: Thanks to the cryptography and security research community
- **Open Source**: Standing on the shoulders of giants in the FOSS community

## 📞 Support

For questions, issues, or feature requests:
- **Issues**: Open an issue on GitHub
- **Discussions**: Use GitHub Discussions for general questions
- **Email**: your.email@example.com
- **Documentation**: Check SECURITY.md for security-related questions

## 🔄 Version History

### v2.0.0 (Current - 2026-01-10)
- ✨ **Security Upgrade**: AES-256-GCM authenticated encryption
- 🔐 **Enhanced Keys**: RSA-4096 and DH-3072
- ➕ **Dual Integrity**: GCM authentication + HMAC-SHA256
- 🎨 **Modern GUI**: Dark theme with status indicators
- 📜 **Chat History**: Persistent storage across sessions
- 🧪 **Attack Tool**: Comprehensive security testing suite
- 📚 **Documentation**: Professional README and inline docs
- ⚡ **Performance**: Batch writes and optimized crypto

### Key Improvements from Earlier Versions
- **Encryption**: Upgraded from legacy algorithms to modern AES-256-GCM
- **Key Sizes**: Enhanced from 2048-bit to 4096-bit (RSA) and 3072-bit (DH)
- **Integrity**: Added multiple layers (GCM tag + HMAC)
- **Features**: Added persistent history, modern GUI, testing tools
- **Security**: Comprehensive replay protection and signature verification

---

## 📊 Feature Comparison

| Feature | Implementation | Security Level |
|---------|---------------|----------------|
| Authentication | X.509 Certificates | ⭐⭐⭐⭐⭐ |
| Key Exchange | DH-3072 | ⭐⭐⭐⭐⭐ |
| Encryption | AES-256-GCM | ⭐⭐⭐⭐⭐ |
| Integrity | Dual-layer (GCM+HMAC) | ⭐⭐⭐⭐⭐ |
| Signatures | RSA-4096-PSS | ⭐⭐⭐⭐⭐ |
| Forward Secrecy | Ephemeral DH | ⭐⭐⭐⭐⭐ |
| Replay Protection | Sequence Numbers | ⭐⭐⭐⭐⭐ |

---

**Made with ❤️ and 🔐 for secure communication**

*"Privacy is not a feature, it's a fundamental right."*
