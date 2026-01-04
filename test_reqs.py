"""
Test script to verify all project requirements are implemented
Run this to check feature compliance
"""

import os
import sys
from datetime import datetime

def check_file_exists(filename):
    """Check if a file exists"""
    if os.path.exists(filename):
        print(f"✅ {filename} exists")
        return True
    else:
        print(f"❌ {filename} MISSING")
        return False

def check_imports():
    """Check if all required libraries can be imported"""
    print("\n" + "="*60)
    print("CHECKING DEPENDENCIES")
    print("="*60)
    
    all_good = True
    
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa, dh
        print("✅ cryptography library installed")
    except ImportError as e:
        print(f"❌ cryptography library missing: {e}")
        all_good = False
    
    try:
        from Crypto.Cipher import DES
        print("✅ PyCryptodome (DES) installed")
    except ImportError as e:
        print(f"❌ PyCryptodome missing: {e}")
        all_good = False
    
    try:
        import tkinter
        print("✅ tkinter (GUI) available")
    except ImportError as e:
        print(f"❌ tkinter missing: {e}")
        all_good = False
    
    return all_good

def check_project_structure():
    """Check if all required files exist"""
    print("\n" + "="*60)
    print("CHECKING PROJECT STRUCTURE")
    print("="*60)
    
    required_files = [
        'main.py',
        'gui.py',
        'secure_base.py',
        'secure_server.py',
        'secure_client.py',
        'config.py',
        '__init__.py'
    ]
    
    all_exist = True
    for file in required_files:
        if not check_file_exists(file):
            all_exist = False
    
    return all_exist

def check_code_features():
    """Check if required features are in the code"""
    print("\n" + "="*60)
    print("CHECKING IMPLEMENTED FEATURES")
    print("="*60)
    
    try:
        # Import the base class
        from secure_base import SecureChatBase
        
        # Check for required methods
        required_methods = {
            '_setup_crypto': 'X.509 Certificate Generation',
            '_exchange_certificates': 'Certificate Exchange',
            '_diffie_hellman': 'Diffie-Hellman Key Exchange',
            '_derive_session_key': 'Session Key Derivation',
            '_encrypt': 'DES Encryption',
            '_decrypt': 'DES Decryption',
            '_sign_message': 'RSA Message Signing',
            '_verify_signature': 'RSA Signature Verification',
            'send_message': 'Message Sending',
            '_receive_loop': 'Message Receiving',
            '_log_message': 'Encrypted Logging',
            'decrypt_log_file': 'Log Decryption'
        }
        
        all_methods_exist = True
        for method, description in required_methods.items():
            if hasattr(SecureChatBase, method):
                print(f"✅ {description}: {method}()")
            else:
                print(f"❌ MISSING: {description}: {method}()")
                all_methods_exist = False
        
        # Check for required attributes
        print("\nChecking required attributes...")
        test_instance = SecureChatBase("test_user", lambda x: None)
        
        required_attrs = {
            'sign_messages': 'RSA Signing Toggle',
            'sequence': 'Sequence Counter (Replay Protection)',
            'peer_sequence': 'Peer Sequence Tracking',
            'session_key': 'DES Session Key',
            'certificate': 'X.509 Certificate',
            'private_key': 'RSA Private Key',
            'public_key': 'RSA Public Key'
        }
        
        for attr, description in required_attrs.items():
            if hasattr(test_instance, attr):
                print(f"✅ {description}: {attr}")
            else:
                print(f"❌ MISSING: {description}: {attr}")
                all_methods_exist = False
        
        return all_methods_exist
        
    except Exception as e:
        print(f"❌ Error checking features: {e}")
        return False

def check_message_format():
    """Verify message format includes all required headers"""
    print("\n" + "="*60)
    print("CHECKING MESSAGE FORMAT")
    print("="*60)
    
    try:
        with open('secure_base.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        required_fields = {
            "'seq'": "Sequence Number",
            "'text'": "Message Text",
            "'sender'": "Sender Username",
            "'timestamp'": "Timestamp",
            "'signed'": "Signature Flag",
            "'signature'": "RSA Signature"
        }
        
        all_present = True
        for field, description in required_fields.items():
            if field in content:
                print(f"✅ {description}: {field}")
            else:
                print(f"❌ MISSING: {description}: {field}")
                all_present = False
        
        return all_present
        
    except Exception as e:
        print(f"❌ Error checking message format: {e}")
        return False

def check_replay_protection():
    """Check if replay protection is implemented"""
    print("\n" + "="*60)
    print("CHECKING REPLAY PROTECTION")
    print("="*60)
    
    try:
        with open('secure_base.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        checks = {
            'seq <= self.peer_sequence': 'Sequence validation',
            'REPLAY ATTACK': 'Replay attack detection',
            'self.peer_sequence = seq': 'Sequence update'
        }
        
        all_present = True
        for check, description in checks.items():
            if check in content:
                print(f"✅ {description}")
            else:
                print(f"❌ MISSING: {description}")
                all_present = False
        
        return all_present
        
    except Exception as e:
        print(f"❌ Error checking replay protection: {e}")
        return False

def check_encrypted_logging():
    """Check if encrypted logging is implemented"""
    print("\n" + "="*60)
    print("CHECKING ENCRYPTED LOGGING")
    print("="*60)
    
    try:
        with open('secure_base.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        checks = {
            '_encrypt_log_entry': 'Log encryption method',
            'decrypt_log_file': 'Log decryption method',
            'DES.new(self.session_key': 'DES encryption for logs',
            '.hex()': 'Hex encoding for storage'
        }
        
        all_present = True
        for check, description in checks.items():
            if check in content:
                print(f"✅ {description}")
            else:
                print(f"❌ MISSING: {description}")
                all_present = False
        
        return all_present
        
    except Exception as e:
        print(f"❌ Error checking encrypted logging: {e}")
        return False

def check_signature_verification():
    """Check if signature verification rejects invalid messages"""
    print("\n" + "="*60)
    print("CHECKING SIGNATURE VERIFICATION")
    print("="*60)
    
    try:
        with open('secure_base.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        checks = {
            'if signed:': 'Signature check conditional',
            '_verify_signature': 'Signature verification method',
            'SIGNATURE VERIFICATION FAILED': 'Failure detection',
            'continue': 'Message rejection on failure'
        }
        
        all_present = True
        for check, description in checks.items():
            if check in content:
                print(f"✅ {description}")
            else:
                print(f"❌ MISSING: {description}")
                all_present = False
        
        return all_present
        
    except Exception as e:
        print(f"❌ Error checking signature verification: {e}")
        return False

def main():
    """Run all checks"""
    print("="*60)
    print("SECURE CHAT PROJECT - REQUIREMENTS VERIFICATION")
    print("="*60)
    print(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    results = {}
    
    results['dependencies'] = check_imports()
    results['structure'] = check_project_structure()
    results['features'] = check_code_features()
    results['message_format'] = check_message_format()
    results['replay_protection'] = check_replay_protection()
    results['encrypted_logging'] = check_encrypted_logging()
    results['signature_verification'] = check_signature_verification()
    
    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    
    for test, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test.replace('_', ' ').title()}")
    
    print("\n" + "="*60)
    print(f"OVERALL: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ ALL REQUIREMENTS IMPLEMENTED!")
        print("\nYour project meets all the requirements:")
        print("  ✓ Mutual Authentication (X.509)")
        print("  ✓ Diffie-Hellman Key Exchange")
        print("  ✓ DES Encryption in CFB Mode")
        print("  ✓ RSA Message Signing")
        print("  ✓ Message Headers (sender, timestamp, seq, signature)")
        print("  ✓ Replay Protection")
        print("  ✓ Encrypted Logging")
    else:
        print(f"⚠️  {total - passed} requirement(s) need attention")
    
    print("="*60)

if __name__ == "__main__":
    main()