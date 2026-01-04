# 🔐 Wanna Chat - Secure End-to-End Encrypted Chat Application

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-AES--256--GCM-brightgreen.svg)](SECURITY.md)
[![Status](https://img.shields.io/badge/status-active-success.svg)]()
[![College Project](https://img.shields.io/badge/origin-college%20project-orange.svg)](IMPROVEMENTS.md)

A secure peer-to-peer chat application implementing modern cryptographic protocols including mutual authentication, Diffie-Hellman key exchange, AES-256 encryption, and digital signatures.

> **Note**: This project evolved from a college assignment to a production-ready implementation. See [IMPROVEMENTS.md](IMPROVEMENTS.md) for the journey from DES to AES-256-GCM.

## ✨ Features

### 🛡️ Security Features
- **Mutual Authentication**: X.509 certificate-based authentication with RSA-4096
- **Key Exchange**: Diffie-Hellman (3072-bit) for secure session key establishment
- **Encryption**: AES-256-GCM for message confidentiality and authenticity
- **Message Integrity**: HMAC-SHA256 for additional integrity verification
- **Digital Signatures**: RSA-4096 with PSS padding for message authenticity
- **Replay Protection**: Sequence number validation to prevent replay attacks
- **Encrypted Logging**: All chat logs encrypted with AES-256-GCM

### 💬 Application Features
- Modern, user-friendly GUI with dark theme
- Persistent chat history across sessions
- Real-time message delivery
- Connection status indicators
- Server/Client mode support

### 🔬 Security Testing Tools
- **Attack Testing Tool**: Built-in MITM proxy for security testing
  - Replay attack simulation
  - Message tampering detection
  - Message dropping (packet loss simulation)
  - Delay attack testing
  - Certificate substitution testing

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/wanna-chat.git
cd wanna-chat
```

2. Install dependencies:
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

#### Start as Client:
```bash
python main.py
```
- Select "Client" role
- Enter username
- Enter server IP address
- Set port (must match server)
- Click "Connect"

### Testing Security Features

Run the attack testing tool:
```bash
python attack_tool.py
```

**Testing Setup:**
1. Start server on a different port (e.g., 5555)
2. Start proxy listening on normal port (5000), forwarding to 5555
3. Client connects to port 5000 (gets intercepted by proxy)
4. Use the attack tool to simulate various attacks

## 🏗️ Architecture

### Cryptographic Protocol Flow

```
1. TCP Connection Established
   ↓
2. Certificate Exchange
   - Both parties exchange X.509 certificates
   - Certificates contain RSA-4096 public keys
   ↓
3. Diffie-Hellman Key Exchange
   - Server generates 3072-bit DH parameters
   - Parameters signed with RSA private key
   - Both parties exchange signed DH public keys
   - Shared secret computed
   ↓
4. Session Key Derivation
   - PBKDF2-HMAC-SHA256 derives:
     * AES-256 encryption key (32 bytes)
     * HMAC-SHA256 key (32 bytes)
   ↓
5. Secure Communication
   - Messages encrypted with AES-256-GCM
   - HMAC-SHA256 for integrity
   - RSA signatures for authenticity
   - Sequence numbers prevent replay
```

### Message Format

```json
{
  "seq": 0,
  "text": "Hello, World!",
  "sender": "Alice",
  "timestamp": "2025-01-04T12:00:00Z",
  "signed": true,
  "signature": "base64_encoded_rsa_signature"
}
```

**Wire Protocol:**
```
[4 bytes: length] [32 bytes: HMAC] [12 bytes: IV] [16 bytes: GCM tag] [variable: ciphertext]
```

## 📁 Project Structure

```
wanna-chat/
├── main.py                 # Application entry point
├── gui.py                  # Modern GUI implementation
├── secure_base.py          # Core cryptographic functionality
├── secure_server.py        # Server implementation
├── secure_client.py        # Client implementation
├── config.py               # Configuration management
├── attack_tool.py          # Security testing tool
├── test_reqs.py           # Requirements verification script
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── LICENSE                # MIT License
├── .gitignore            # Git ignore rules
└── chat_history/         # Persistent chat storage (auto-created)
```

## 🔒 Security Specifications

### Algorithms Used

| Component | Algorithm | Key Size |
|-----------|-----------|----------|
| Asymmetric Encryption | RSA | 4096 bits |
| Key Exchange | Diffie-Hellman | 3072 bits |
| Symmetric Encryption | AES-GCM | 256 bits |
| Message Integrity | HMAC-SHA256 | 256 bits |
| Digital Signature | RSA-PSS-SHA256 | 4096 bits |
| Key Derivation | PBKDF2-HMAC-SHA256 | 100,000 iterations |

### Security Properties

✅ **Confidentiality**: AES-256-GCM encryption protects message content  
✅ **Integrity**: HMAC-SHA256 and GCM authentication detect tampering  
✅ **Authenticity**: RSA-4096 signatures verify sender identity  
✅ **Forward Secrecy**: Diffie-Hellman provides session-specific keys  
✅ **Replay Protection**: Sequence numbers prevent message replay  
✅ **Non-Repudiation**: Digital signatures provide proof of origin  

## 🧪 Testing

### Run Requirement Verification
```bash
python test_reqs.py
```

This checks:
- All required files exist
- Dependencies are installed
- Security features are implemented
- Message format is correct
- Replay protection works
- Signature verification functions

### Manual Security Testing

1. **Normal Operation Test**:
   - Start server and client
   - Exchange messages
   - Verify encryption/decryption works

2. **Replay Attack Test**:
   - Use attack tool to intercept messages
   - Replay captured message
   - Verify "REPLAY ATTACK DETECTED" appears

3. **Tampering Test**:
   - Use attack tool to modify message bits
   - Verify message rejected (HMAC/GCM failure)

4. **Man-in-the-Middle Test**:
   - Position attack tool between client/server
   - Observe that content remains encrypted
   - Attempt certificate substitution

## 📊 Performance

- **Handshake Time**: ~2-3 seconds (includes DH-3072 generation)
- **Message Latency**: <50ms (local network)
- **Throughput**: Limited by Python GIL, suitable for chat
- **Key Generation**: RSA-4096 ~1-2s, DH-3072 ~1-2s

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Security Disclaimer

This application is designed for educational purposes to demonstrate secure communication protocols. While it implements industry-standard cryptographic algorithms, it has not undergone professional security audit. For production use, consider:

- Professional security audit
- Proper certificate authority infrastructure
- Key rotation policies
- Enhanced error handling
- Rate limiting and DoS protection
- User authentication system

## 👥 Authors

- **Your Name** - Upgraded from DES to AES-256, enhanced security algorithms, improved architecture

## 🎓 Project History

This project originated as a college assignment for **[Your Course Name/Number]** at **[Your University]**. The original version implemented:
- Basic secure chat with DES encryption
- RSA-2048 and DH-2048 
- Fundamental cryptographic concepts

**Post-graduation improvements** (this version):
- ✨ Upgraded encryption: DES → AES-256-GCM
- 🔐 Enhanced key sizes: RSA-2048 → RSA-4096, DH-2048 → DH-3072
- 🛡️ Added HMAC-SHA256 for additional integrity
- 🎨 Modernized GUI with better UX
- 📚 Professional documentation and CI/CD
- 🧪 Enhanced security testing tools
- 📜 Persistent chat history feature

## 🙏 Acknowledgments

- **Academic Foundation**: Original project developed for [Course Name] at [University]
- **Professor/Instructor**: [Name] - For teaching cryptographic principles
- **Libraries**: Built with [cryptography](https://cryptography.io/) library
- **Protocols**: Implements concepts from TLS/SSL and Signal Protocol
- **Inspiration**: Modern secure messaging applications

## 📞 Support

For questions or issues:
- Open an issue on GitHub
- Email: your.email@example.com

## 🔄 Version History

### v2.0.0 (2025-01-04)
- ✨ Upgraded from DES to AES-256-GCM
- 🔐 Enhanced RSA from 2048 to 4096 bits
- 🔑 Enhanced DH from 2048 to 3072 bits
- ➕ Added HMAC-SHA256 for message integrity
- 🎨 Improved GUI with modern design
- 📜 Added persistent chat history
- 🧪 Enhanced attack testing tool

### v1.0.0 (Original College Project)
- Initial release with DES encryption
- Basic RSA-2048 and DH-2048
- Simple GUI interface

**See [IMPROVEMENTS.md](IMPROVEMENTS.md) for detailed comparison**

| Feature | v1.0 (College) | v2.0 (Enhanced) |
|---------|----------------|-----------------|
| Encryption | DES-CFB (64-bit) | AES-256-GCM |
| RSA Keys | 2048 bits | 4096 bits |
| DH Exchange | 2048 bits | 3072 bits |
| Integrity | 1 layer | 3 layers |
| Documentation | Basic | Professional |
| CI/CD | None | GitHub Actions |

---

**Made with ❤️ and 🔐 for secure communication**