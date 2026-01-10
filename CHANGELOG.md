# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-01-10

### 🚀 Production-Grade Enhancement Release

This release represents a significant upgrade from the original academic project, bringing it up to modern security standards and professional software development practices.

### 🔒 Security Enhancements

#### Added
- **AES-256-GCM encryption** (upgraded from AES-128-CBC)
  - Provides authenticated encryption with associated data (AEAD)
  - 256-bit key size for enhanced security
  - 12-byte IV (recommended for GCM mode)
  - Built-in authentication tag prevents tampering
  - Eliminates padding oracle vulnerabilities
  
- **HMAC-SHA256** for additional message integrity
  - Separate 32-byte HMAC key derived from shared secret
  - Defense-in-depth: double layer of integrity protection (GCM + HMAC)
  
- **Enhanced key sizes**
  - RSA upgraded from 2048 to 4096 bits
  - Diffie-Hellman upgraded from 2048 to 3072 bits
  - Meets current NIST recommendations (SP 800-57)
  - Future-proofed against computational advances
  
- **PBKDF2 key derivation**
  - 100,000 iterations of HMAC-SHA-256
  - Derives separate encryption and MAC keys (64 bytes total)
  - Prevents weak key generation from DH shared secret
  - Industry-standard key stretching

#### Changed
- Encryption mode: AES-CBC → AES-GCM (AEAD)
- Key derivation: Simple SHA-256 → PBKDF2-HMAC-SHA256
- Certificate buffer size: 4096 → 8192 bytes (for RSA-4096)
- Signature scheme: RSA-PKCS1v15 → RSA-PSS (probabilistic)
- Message wire format updated:
  ```
  Old: [length(4)][IV(16)][ciphertext]
  New: [length(4)][HMAC(32)][IV(12)][GCM-tag(16)][ciphertext]
  ```

#### Security Features
- ✅ Triple-layer integrity protection (GCM + HMAC + RSA signatures)
- ✅ Replay attack protection via sequence numbers
- ✅ Mutual authentication with X.509 certificates
- ✅ Perfect forward secrecy via ephemeral DH keys
- ✅ Signature verification on all signed messages
- ✅ Constant-time operations where applicable

### 🎨 User Interface

#### Added
- Modern dark theme with professional color scheme
- Real-time connection status indicator with visual feedback
- Message timestamps in readable format
- Enhanced message formatting with sender names
- Loading states during connection and handshake
- Setup screen with better visual hierarchy

#### Changed
- Cleaner, more intuitive setup screen
- Better visual distinction between sent/received messages
- Improved button hover effects and interactions
- More informative error messages
- Smoother transitions and animations

#### Fixed
- GUI freezing during long operations
- Thread safety issues with Tkinter updates
- Message display race conditions

### 💬 Features

#### Added
- **Persistent chat history**
  - JSON-based storage per conversation pair
  - Automatic loading on reconnection
  - Shows last 50 messages by default (configurable)
  - Batch writing for I/O performance
  - Thread-safe write operations
  
- **Enhanced logging system**
  - Encrypted logs using AES-256-GCM
  - UTC timestamps for consistency
  - Log decryption utility method
  - Non-blocking threaded logging
  - Structured log format

- **Connection management**
  - Configurable timeouts for different operations
  - Graceful disconnect handling
  - Automatic resource cleanup
  - Better error recovery

#### Changed
- Improved message queuing mechanism
- Enhanced error messages with actionable information
- Better timeout handling (separate for handshake vs chat)
- More responsive GUI updates

#### Fixed
- Race condition in message receiving
- Buffer overflow with large certificates
- History file creation on first run
- Thread safety in GUI callback

### 🧪 Testing & Development

#### Added
- Enhanced attack testing tool with improved UI
- Clear MITM proxy setup instructions
- Connection status tracking in attack tool
- Multiple documented attack scenarios
- Educational feedback for each attack type
- Visual logging of intercepted traffic

#### Changed
- Attack tool now clearly shows interception position
- Better simulation of real-world attacks
- Improved feedback on attack outcomes
- More descriptive attack descriptions

#### Testing Enhancements
- Updated `test_reqs.py` for AES-256-GCM
- Verification of all security features
- Encryption strength validation
- Key size verification
- Protocol compliance checking

### 📚 Documentation

#### Added
- **README.md** - Comprehensive project documentation
  - Architecture overview with diagrams
  - Detailed security specifications
  - Installation and usage instructions
  - Troubleshooting guide
  - Performance considerations
  
- **IMPROVEMENTS.md** - Enhancement documentation
  - Comparison of v1.0 vs v2.0
  - Rationale for each improvement
  - Learning outcomes
  - Future roadmap
  
- **CHANGELOG.md** - This file
  - Detailed version history
  - Migration guides
  - Breaking changes documentation

#### Changed
- Updated all inline code comments
- Enhanced docstrings for all methods
- Improved debug logging messages
- Better error messages

### 🔧 Technical

#### Added
- Type hints for improved code clarity
- Comprehensive error handling with specific exceptions
- Debug logging throughout the codebase
- Socket timeout configuration per operation
- Thread-safe GUI update mechanism
- Resource cleanup on errors

#### Changed
- Modular code organization
- Improved separation of concerns
- Better encapsulation
- Enhanced exception hierarchy
- More efficient data structures

#### Performance
- Batched history writes (reduces I/O)
- Lazy loading of chat history
- Non-blocking logging operations
- Efficient message queuing
- Optimized GUI updates

### 🐛 Bug Fixes
- Fixed race conditions in message receiving loop
- Corrected buffer size for RSA-4096 certificates
- Fixed history file creation on Windows
- Resolved GUI thread safety problems
- Fixed socket timeout issues during handshake
- Corrected IV generation for GCM mode
- Fixed graceful shutdown sequence

### 🔄 Breaking Changes

#### Protocol Changes
- **Wire format is incompatible** - v2.0 cannot communicate with v1.0
- Message structure changed (added HMAC, different IV size)
- Handshake extended for enhanced parameters

#### API Changes
- `_encrypt()` now returns `(iv, ciphertext, tag)` tuple
- `_decrypt()` requires `tag` parameter
- Key derivation produces 64 bytes (was 32)
- Signature verification uses PSS padding

#### Migration Required
- Old encrypted logs cannot be decrypted with v2.0
- Chat history format is backward compatible
- Certificates need regeneration (different sizes)

---

## [1.0.0] - 2025-12-15 (Academic Release)

### 🎓 Initial Academic Version

Original college assignment demonstrating cryptographic concepts.

#### Educational Objectives Met
- ✅ Implemented symmetric encryption (AES-128-CBC)
- ✅ Implemented asymmetric encryption (RSA-2048)
- ✅ Demonstrated key exchange (Diffie-Hellman 2048)
- ✅ Applied digital signatures (RSA-SHA256)
- ✅ Understood PKI concepts (X.509 certificates)
- ✅ Implemented replay attack protection (sequence numbers)

#### Features
- Basic secure chat functionality
- AES-128 encryption in CBC mode
- RSA-2048 for signatures and certificates
- Diffie-Hellman 2048-bit key exchange
- X.509 certificate-based authentication
- Replay attack protection via sequence numbers
- Simple Tkinter GUI interface
- Basic attack testing tool

#### Security Implementation
- AES-128-CBC for message encryption
- RSA-2048 signatures with SHA-256
- DH-2048 key exchange
- Sequence number validation
- Self-signed X.509 certificates
- Simple certificate exchange protocol

#### Known Limitations
- Smaller key sizes (RSA-2048, DH-2048)
- CBC mode requires separate MAC
- No persistent chat history
- Basic error handling
- Limited documentation
- No automated testing

---

## Migration Guide: v1.0 → v2.0

### ⚠️ Breaking Changes Summary

1. **Wire Protocol Incompatible**
   - Message format completely changed
   - Different encryption mode (CBC → GCM)
   - Additional integrity layers (HMAC)
   - v2.0 clients cannot talk to v1.0 servers

2. **Encrypted Logs Incompatible**
   - Different encryption parameters
   - Old logs cannot be decrypted with v2.0
   - **Action Required**: Decrypt and save old logs before upgrading

3. **Certificate Size Changed**
   - RSA-2048 → RSA-4096
   - Larger certificate exchange buffer needed
   - Old certificates will work but should be regenerated

### Upgrade Steps

```bash
# 1. Backup existing data
mkdir backup_v1
cp -r chat_history/ backup_v1/
cp *.log backup_v1/

# 2. Decrypt old logs (while still on v1.0)
python -c "from secure_base import SecureChatBase; \
           chat = SecureChatBase('backup', lambda x:x); \
           chat.decrypt_log_file()"

# 3. Update code
git fetch origin
git checkout v2.0

# 4. Update dependencies
pip install --upgrade cryptography

# 5. Test new version
python test_reqs.py

# 6. Start fresh or import history
# History JSON files are compatible
```

### What Stays Compatible

✅ Chat history JSON format (backward compatible)  
✅ GUI workflow and user experience  
✅ Configuration file format  
✅ Attack tool interface  
✅ Basic usage patterns  

### What Requires Changes

❌ Cannot connect v1.0 ↔ v2.0 (protocol incompatible)  
❌ Old encrypted logs need decryption before upgrade  
❌ Certificates should be regenerated (different key size)  
❌ Any custom code using `_encrypt()/_decrypt()` API  

---

## Version History Summary

| Version | Release Date | Key Feature | Security Level |
|---------|-------------|-------------|----------------|
| 1.0.0 | 2025-12-15 | Academic implementation | Educational |
| 2.0.0 | 2026-01-10 | Production-grade crypto | Professional |

---

## Versioning Strategy

This project follows [Semantic Versioning](https://semver.org/):

- **Major version** (X.0.0): Breaking changes, protocol changes, incompatible updates
- **Minor version** (0.X.0): New features, backward compatible additions
- **Patch version** (0.0.X): Bug fixes, no new features, fully compatible

### Future Version Plans

- **v2.1.0**: Group chat support, file transfer
- **v2.2.0**: Web interface, mobile support
- **v3.0.0**: Post-quantum cryptography, federation protocol

---

## Links & Resources

- **Repository**: [GitHub](https://github.com/yourusername/wanna-chat)
- **Issues**: [Bug Reports](https://github.com/yourusername/wanna-chat/issues)
- **Security**: [Security Policy](SECURITY.md)
- **Contributing**: [Contribution Guidelines](CONTRIBUTING.md)
- **Documentation**: [Full Docs](README.md)

---

## Acknowledgments

- NIST for cryptographic standards and guidelines
- PyCA cryptography library maintainers
- Academic advisors for foundational knowledge
- Security community for best practices

---

**Note**: This project demonstrates continuous learning and improvement from academic foundation to professional implementation.

*Last Updated: January 10, 2026*
