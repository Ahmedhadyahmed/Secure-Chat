# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-01-04

### 🎓 Post-College Enhancement Release

This release represents a significant upgrade from the original college project, bringing it up to modern security standards and professional software development practices.

### 🔒 Security Enhancements

#### Added
- **AES-256-GCM encryption** replacing legacy DES
  - Provides authenticated encryption with associated data (AEAD)
  - 256-bit key size for enhanced security
  - 12-byte IV (recommended for GCM mode)
  - Built-in authentication tag prevents tampering
  
- **HMAC-SHA256** for additional message integrity
  - Separate 32-byte HMAC key derived from shared secret
  - Double layer of integrity protection (GCM + HMAC)
  
- **Enhanced key sizes**
  - RSA upgraded from 2048 to 4096 bits
  - Diffie-Hellman upgraded from 2048 to 3072 bits
  - Meets current NIST recommendations
  
- **PBKDF2 key derivation**
  - 100,000 iterations of SHA-256
  - Derives separate encryption and MAC keys
  - Prevents weak key generation from DH shared secret

#### Changed
- All encryption operations now use AES-256-GCM instead of DES-CFB
- Certificate size increased due to RSA-4096 (recv buffer: 4096→8192 bytes)
- Message wire format updated:
  ```
  Old: [length][IV-8][ciphertext]
  New: [length][HMAC-32][IV-12][GCM-tag-16][ciphertext]
  ```

#### Removed
- Dependency on `pycryptodome` (DES implementation)
- DES-CFB encryption mode
- 8-byte IV usage

### 🎨 User Interface

#### Added
- Modern dark theme with improved color scheme
- Connection status indicator with visual feedback
- Real-time message timestamps
- Enhanced message formatting
- Loading states during connection

#### Changed
- Cleaner setup screen layout
- Better visual hierarchy
- Improved button hover effects
- More intuitive role selection

### 💬 Features

#### Added
- **Persistent chat history**
  - JSON-based storage per conversation pair
  - Automatic loading on reconnection
  - Shows last 50 messages (configurable)
  - Batch writing for performance
  
- **Enhanced logging**
  - Encrypted logs with AES-256-GCM
  - Timestamp with UTC timezone
  - Log decryption utility
  - Threaded logging (non-blocking)

#### Changed
- Improved error messages
- Better connection handling
- Enhanced timeout management
- Thread-safe GUI updates

### 🧪 Testing

#### Added
- Enhanced attack testing tool with better UI
- Clear setup instructions in attack tool
- Connection status tracking
- Multiple attack scenarios documented

#### Changed
- Attack tool now shows MITM position clearly
- Better logging of intercepted traffic
- Improved attack simulation feedback

### 📚 Documentation

#### Added
- Comprehensive README.md
- SECURITY.md with security policy
- CONTRIBUTING.md with contribution guidelines
- CHANGELOG.md (this file)
- LICENSE file (MIT)
- .gitignore for Python projects

#### Changed
- Updated setup instructions
- Added architecture diagrams
- Enhanced security specifications
- Added troubleshooting section

### 🔧 Technical

#### Added
- Type hints for better code clarity
- Enhanced error handling
- Better debug logging
- Socket timeout configuration

#### Changed
- Modular code organization
- Improved thread safety
- Better resource cleanup
- Enhanced exception handling

### 🐛 Bug Fixes
- Fixed race conditions in message receiving
- Corrected buffer size for large certificates
- Fixed history file creation issues
- Resolved GUI thread safety problems

---

## [1.0.0] - 2024-XX-XX (College Project)

### 🎓 Academic Version

This was the original college assignment demonstrating understanding of cryptographic principles.

#### Educational Objectives Met
- ✅ Implemented symmetric encryption (DES)
- ✅ Implemented asymmetric encryption (RSA)
- ✅ Demonstrated key exchange (Diffie-Hellman)
- ✅ Applied digital signatures
- ✅ Understood PKI concepts (X.509)
- ✅ Implemented replay attack protection

#### Features
- Basic secure chat functionality
- DES encryption in CFB mode
- RSA-2048 for signatures
- Diffie-Hellman-2048 key exchange
- X.509 certificate authentication
- Replay attack protection
- Simple GUI interface
- Attack testing tool

#### Security
- DES-CFB encryption
- RSA-2048 signatures
- DH-2048 key exchange
- Sequence number tracking
- Basic certificate exchange

---

## Migration Guide: v1.0 → v2.0

### Breaking Changes

1. **Wire Protocol**: v2.0 messages are incompatible with v1.0
   - Different message format (HMAC, longer IV, GCM tag)
   - v2.0 clients cannot communicate with v1.0 servers

2. **Dependencies**: `pycryptodome` no longer required
   - Remove: `pip uninstall pycryptodome`
   - Everything now uses `cryptography` library

3. **Log Format**: Encrypted logs use different format
   - Old logs cannot be decrypted with v2.0
   - Save/export old logs before upgrading

### Upgrade Steps

```bash
# 1. Backup old chat logs
cp -r chat_history chat_history_backup_v1

# 2. Update code
git pull origin main

# 3. Update dependencies
pip install -r requirements.txt

# 4. Remove old dependency
pip uninstall pycryptodome

# 5. Test new version
python test_reqs.py
```

### What Stays the Same

✅ GUI usage remains similar  
✅ Server/client setup process unchanged  
✅ Attack testing tool interface similar  
✅ Configuration options compatible  

---

## Versioning Strategy

- **Major version** (X.0.0): Breaking changes, protocol changes
- **Minor version** (0.X.0): New features, backward compatible
- **Patch version** (0.0.X): Bug fixes, no new features

## Links

- [Repository](https://github.com/yourusername/wanna-chat)
- [Issues](https://github.com/yourusername/wanna-chat/issues)
- [Security Policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

---

**Note**: This project follows semantic versioning. For more details, see [semver.org](https://semver.org/).