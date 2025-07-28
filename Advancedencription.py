#!/usr/bin/env python3
"""
Advanced Encryption Tool
A robust encryption application with AES-256 and other algorithms
Author: CODTECH Intern
"""

import os
import sys
import json
import base64
import hashlib
import secrets
import argparse
from datetime import datetime
from pathlib import Path
from getpass import getpass

# Cryptography imports
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding, hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
except ImportError:
    print("Error: cryptography library not installed")
    print("Install with: pip install cryptography")
    sys.exit(1)


class Colors:
    """Terminal colors for better UI."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class AdvancedEncryptionTool:
    """Main encryption tool class with multiple algorithms support."""
    
    def __init__(self):
        self.banner = f"""{Colors.CYAN}
╔══════════════════════════════════════════════╗
║        ADVANCED ENCRYPTION TOOL              ║
║           CODTECH Internship                 ║
╚══════════════════════════════════════════════╝{Colors.ENDC}
"""
        self.algorithms = {
            '1': 'AES-256-CBC',
            '2': 'AES-256-GCM',
            '3': 'Fernet (Symmetric)',
            '4': 'RSA-2048 (Asymmetric)',
            '5': 'ChaCha20-Poly1305'
        }
        
    def print_banner(self):
        """Print application banner."""
        print(self.banner)
    
    def generate_key(self, password, salt=None, iterations=100000):
        """Generate encryption key from password using PBKDF2."""
        if salt is None:
            salt = os.urandom(32)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key, salt
    
    def encrypt_aes_cbc(self, data, password):
        """Encrypt data using AES-256-CBC."""
        # Generate key and IV
        key, salt = self.generate_key(password)
        iv = os.urandom(16)
        
        # Pad the data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return salt + iv + ciphertext
        return salt + iv + ciphertext
    
    def decrypt_aes_cbc(self, encrypted_data, password):
        """Decrypt data using AES-256-CBC."""
        # Extract components
        salt = encrypted_data[:32]
        iv = encrypted_data[32:48]
        ciphertext = encrypted_data[48:]
        
        # Derive key
        key, _ = self.generate_key(password, salt)
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    
    def encrypt_aes_gcm(self, data, password):
        """Encrypt data using AES-256-GCM (authenticated encryption)."""
        # Generate key and nonce
        key, salt = self.generate_key(password)
        nonce = os.urandom(12)
        
        # Encrypt with authentication
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Return salt + nonce + tag + ciphertext
        return salt + nonce + encryptor.tag + ciphertext
    
    def decrypt_aes_gcm(self, encrypted_data, password):
        """Decrypt data using AES-256-GCM."""
        # Extract components
        salt = encrypted_data[:32]
        nonce = encrypted_data[32:44]
        tag = encrypted_data[44:60]
        ciphertext = encrypted_data[60:]
        
        # Derive key
        key, _ = self.generate_key(password, salt)
        
        # Decrypt and verify
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    
    def encrypt_fernet(self, data, password):
        """Encrypt data using Fernet (simple symmetric encryption)."""
        # Generate key from password
        key, salt = self.generate_key(password)
        
        # Create Fernet key
        fernet_key = base64.urlsafe_b64encode(key)
        f = Fernet(fernet_key)
        
        # Encrypt
        encrypted = f.encrypt(data)
        
        # Return salt + encrypted data
        return salt + encrypted
    
    def decrypt_fernet(self, encrypted_data, password):
        """Decrypt data using Fernet."""
        # Extract components
        salt = encrypted_data[:32]
        ciphertext = encrypted_data[32:]
        
        # Derive key
        key, _ = self.generate_key(password, salt)
        
        # Create Fernet key
        fernet_key = base64.urlsafe_b64encode(key)
        f = Fernet(fernet_key)
        
        # Decrypt
        plaintext = f.decrypt(ciphertext)
        
        return plaintext
    
    def generate_rsa_keys(self):
        """Generate RSA key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def save_rsa_keys(self, private_key, public_key, password=None):
        """Save RSA keys to files."""
        # Save private key
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption = serialization.NoEncryption()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        # Save public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Write to files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        with open(f'private_key_{timestamp}.pem', 'wb') as f:
            f.write(private_pem)
        
        with open(f'public_key_{timestamp}.pem', 'wb') as f:
            f.write(public_pem)
        
        print(f"{Colors.GREEN}[+] Keys saved:{Colors.ENDC}")
        print(f"    Private: private_key_{timestamp}.pem")
        print(f"    Public: public_key_{timestamp}.pem")
        
        return f'private_key_{timestamp}.pem', f'public_key_{timestamp}.pem'
    
    def load_rsa_key(self, key_path, is_private=True, password=None):
        """Load RSA key from file."""
        with open(key_path, 'rb') as f:
            key_data = f.read()
        
        if is_private:
            if password:
                return serialization.load_pem_private_key(
                    key_data, password.encode(), backend=default_backend()
                )
            else:
                return serialization.load_pem_private_key(
                    key_data, None, backend=default_backend()
                )
        else:
            return serialization.load_pem_public_key(
                key_data, backend=default_backend()
            )
    
    def encrypt_rsa(self, data, public_key):
        """Encrypt data using RSA."""
        # RSA can only encrypt small amounts of data
        # For larger data, we use hybrid encryption
        
        # Generate symmetric key
        sym_key = os.urandom(32)
        
        # Encrypt data with symmetric key
        f = Fernet(base64.urlsafe_b64encode(sym_key))
        encrypted_data = f.encrypt(data)
        
        # Encrypt symmetric key with RSA
        encrypted_key = public_key.encrypt(
            sym_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return encrypted key + encrypted data
        return encrypted_key + encrypted_data
    
    def decrypt_rsa(self, encrypted_data, private_key):
        """Decrypt data using RSA."""
        # Extract components
        encrypted_key = encrypted_data[:256]  # RSA-2048 produces 256-byte ciphertext
        encrypted_content = encrypted_data[256:]
        
        # Decrypt symmetric key
        sym_key = private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt data with symmetric key
        f = Fernet(base64.urlsafe_b64encode(sym_key))
        plaintext = f.decrypt(encrypted_content)
        
        return plaintext
    
    def encrypt_chacha20(self, data, password):
        """Encrypt data using ChaCha20-Poly1305."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        except ImportError:
            print(f"{Colors.FAIL}[!] ChaCha20-Poly1305 not available{Colors.ENDC}")
            return None
        
        # Generate key
        key, salt = self.generate_key(password)
        
        # Create cipher
        chacha = ChaCha20Poly1305(key)
        
        # Generate nonce
        nonce = os.urandom(12)
        
        # Encrypt
        ciphertext = chacha.encrypt(nonce, data, None)
        
        # Return salt + nonce + ciphertext
        return salt + nonce + ciphertext
    
    def decrypt_chacha20(self, encrypted_data, password):
        """Decrypt data using ChaCha20-Poly1305."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        except ImportError:
            print(f"{Colors.FAIL}[!] ChaCha20-Poly1305 not available{Colors.ENDC}")
            return None
        
        # Extract components
        salt = encrypted_data[:32]
        nonce = encrypted_data[32:44]
        ciphertext = encrypted_data[44:]
        
        # Derive key
        key, _ = self.generate_key(password, salt)
        
        # Create cipher
        chacha = ChaCha20Poly1305(key)
        
        # Decrypt
        plaintext = chacha.decrypt(nonce, ciphertext, None)
        
        return plaintext
    
    def encrypt_file(self, filepath, algorithm, password=None, public_key_path=None):
        """Encrypt a file."""
        try:
            # Read file
            with open(filepath, 'rb') as f:
                data = f.read()
            
            print(f"[*] Encrypting {filepath} ({len(data)} bytes)...")
            
            # Encrypt based on algorithm
            if algorithm == '1':  # AES-256-CBC
                encrypted = self.encrypt_aes_cbc(data, password)
            elif algorithm == '2':  # AES-256-GCM
                encrypted = self.encrypt_aes_gcm(data, password)
            elif algorithm == '3':  # Fernet
                encrypted = self.encrypt_fernet(data, password)
            elif algorithm == '4':  # RSA
                public_key = self.load_rsa_key(public_key_path, is_private=False)
                encrypted = self.encrypt_rsa(data, public_key)
            elif algorithm == '5':  # ChaCha20
                encrypted = self.encrypt_chacha20(data, password)
            else:
                print(f"{Colors.FAIL}[!] Invalid algorithm{Colors.ENDC}")
                return False
            
            # Save encrypted file
            output_path = f"{filepath}.enc"
            with open(output_path, 'wb') as f:
                # Write metadata
                metadata = {
                    'algorithm': self.algorithms[algorithm],
                    'original_name': os.path.basename(filepath),
                    'timestamp': datetime.now().isoformat()
                }
                metadata_json = json.dumps(metadata).encode()
                f.write(len(metadata_json).to_bytes(4, 'big'))
                f.write(metadata_json)
                f.write(encrypted)
            
            print(f"{Colors.GREEN}[+] File encrypted successfully!{Colors.ENDC}")
            print(f"    Output: {output_path}")
            
            # Option to delete original
            if input("\nDelete original file? (y/N): ").lower() == 'y':
                os.remove(filepath)
                print(f"{Colors.WARNING}[!] Original file deleted{Colors.ENDC}")
            
            return True
            
        except Exception as e:
            print(f"{Colors.FAIL}[!] Encryption failed: {e}{Colors.ENDC}")
            return False
    
    def decrypt_file(self, filepath, password=None, private_key_path=None):
        """Decrypt a file."""
        try:
            # Read encrypted file
            with open(filepath, 'rb') as f:
                # Read metadata
                metadata_len = int.from_bytes(f.read(4), 'big')
                metadata_json = f.read(metadata_len)
                metadata = json.loads(metadata_json.decode())
                encrypted = f.read()
            
            print(f"[*] Decrypting {filepath}")
            print(f"    Algorithm: {metadata['algorithm']}")
            print(f"    Original name: {metadata['original_name']}")
            
            # Decrypt based on algorithm
            if metadata['algorithm'] == 'AES-256-CBC':
                decrypted = self.decrypt_aes_cbc(encrypted, password)
            elif metadata['algorithm'] == 'AES-256-GCM':
                decrypted = self.decrypt_aes_gcm(encrypted, password)
            elif metadata['algorithm'] == 'Fernet (Symmetric)':
                decrypted = self.decrypt_fernet(encrypted, password)
            elif metadata['algorithm'] == 'RSA-2048 (Asymmetric)':
                private_key = self.load_rsa_key(private_key_path, is_private=True, password=password)
                decrypted = self.decrypt_rsa(encrypted, private_key)
            elif metadata['algorithm'] == 'ChaCha20-Poly1305':
                decrypted = self.decrypt_chacha20(encrypted, password)
            else:
                print(f"{Colors.FAIL}[!] Unknown algorithm{Colors.ENDC}")
                return False
            
            # Save decrypted file
            output_path = metadata['original_name']
            if os.path.exists(output_path):
                output_path = f"decrypted_{metadata['original_name']}"
            
            with open(output_path, 'wb') as f:
                f.write(decrypted)
            
            print(f"{Colors.GREEN}[+] File decrypted successfully!{Colors.ENDC}")
            print(f"    Output: {output_path}")
            
            return True
            
        except Exception as e:
            print(f"{Colors.FAIL}[!] Decryption failed: {e}{Colors.ENDC}")
            print("    Possible causes:")
            print("    - Incorrect password")
            print("    - Corrupted file")
            print("    - Wrong private key")
            return False
    
    def encrypt_text(self, text, algorithm, password=None, public_key_path=None):
        """Encrypt text string."""
        data = text.encode('utf-8')
        
        # Encrypt based on algorithm
        if algorithm == '1':  # AES-256-CBC
            encrypted = self.encrypt_aes_cbc(data, password)
        elif algorithm == '2':  # AES-256-GCM
            encrypted = self.encrypt_aes_gcm(data, password)
        elif algorithm == '3':  # Fernet
            encrypted = self.encrypt_fernet(data, password)
        elif algorithm == '4':  # RSA
            public_key = self.load_rsa_key(public_key_path, is_private=False)
            encrypted = self.encrypt_rsa(data, public_key)
        elif algorithm == '5':  # ChaCha20
            encrypted = self.encrypt_chacha20(data, password)
        else:
            return None
        
        # Encode to base64 for display
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt_text(self, encrypted_text, algorithm, password=None, private_key_path=None):
        """Decrypt text string."""
        # Decode from base64
        encrypted = base64.b64decode(encrypted_text.encode('utf-8'))
        
        # Decrypt based on algorithm
        if algorithm == '1':  # AES-256-CBC
            decrypted = self.decrypt_aes_cbc(encrypted, password)
        elif algorithm == '2':  # AES-256-GCM
            decrypted = self.decrypt_aes_gcm(encrypted, password)
        elif algorithm == '3':  # Fernet
            decrypted = self.decrypt_fernet(encrypted, password)
        elif algorithm == '4':  # RSA
            private_key = self.load_rsa_key(private_key_path, is_private=True, password=password)
            decrypted = self.decrypt_rsa(encrypted, private_key)
        elif algorithm == '5':  # ChaCha20
            decrypted = self.decrypt_chacha20(encrypted, password)
        else:
            return None
        
        return decrypted.decode('utf-8')
    
    def secure_delete(self, filepath, passes=3):
        """Securely delete a file by overwriting it multiple times."""
        try:
            filesize = os.path.getsize(filepath)
            
            with open(filepath, 'rb+') as f:
                for pass_num in range(passes):
                    print(f"[*] Overwrite pass {pass_num + 1}/{passes}")
                    f.seek(0)
                    
                    if pass_num == 0:
                        # First pass: random data
                        f.write(os.urandom(filesize))
                    elif pass_num == 1:
                        # Second pass: zeros
                        f.write(b'\x00' * filesize)
                    else:
                        # Final pass: random data
                        f.write(os.urandom(filesize))
                    
                    f.flush()
                    os.fsync(f.fileno())
            
            # Delete the file
            os.remove(filepath)
            print(f"{Colors.GREEN}[+] File securely deleted{Colors.ENDC}")
            return True
            
        except Exception as e:
            print(f"{Colors.FAIL}[!] Secure delete failed: {e}{Colors.ENDC}")
            return False
    
    def benchmark_algorithms(self):
        """Benchmark encryption algorithms."""
        print(f"\n{Colors.HEADER}[*] Benchmarking Encryption Algorithms{Colors.ENDC}")
        print("-" * 50)
        
        # Test data
        test_sizes = [1024, 10240, 102400]  # 1KB, 10KB, 100KB
        password = "benchmark_password"
        
        for size in test_sizes:
            print(f"\nTesting with {size} bytes of data:")
            data = os.urandom(size)
            
            # Test each algorithm
            for alg_id, alg_name in self.algorithms.items():
                if alg_id == '4':  # Skip RSA for benchmark
                    continue
                
                try:
                    import time
                    start = time.time()
                    
                    if alg_id == '1':
                        encrypted = self.encrypt_aes_cbc(data, password)
                        self.decrypt_aes_cbc(encrypted, password)
                    elif alg_id == '2':
                        encrypted = self.encrypt_aes_gcm(data, password)
                        self.decrypt_aes_gcm(encrypted, password)
                    elif alg_id == '3':
                        encrypted = self.encrypt_fernet(data, password)
                        self.decrypt_fernet(encrypted, password)
                    elif alg_id == '5':
                        encrypted = self.encrypt_chacha20(data, password)
                        if encrypted:
                            self.decrypt_chacha20(encrypted, password)
                    
                    elapsed = time.time() - start
                    print(f"  {alg_name}: {elapsed:.4f} seconds")
                    
                except Exception as e:
                    print(f"  {alg_name}: Failed - {e}")
    
    def interactive_mode(self):
        """Run interactive mode with menu."""
        while True:
            print(f"\n{Colors.HEADER}Main Menu:{Colors.ENDC}")
            print("1. Encrypt File")
            print("2. Decrypt File")
            print("3. Encrypt Text")
            print("4. Decrypt Text")
            print("5. Generate RSA Keys")
            print("6. Secure Delete")
            print("7. Benchmark Algorithms")
            print("0. Exit")
            
            choice = input(f"\n{Colors.BOLD}Select option >> {Colors.ENDC}")
            
            if choice == '1':
                # Encrypt file
                filepath = input("Enter file path: ")
                if not os.path.exists(filepath):
                    print(f"{Colors.FAIL}[!] File not found{Colors.ENDC}")
                    continue
                
                print("\nSelect algorithm:")
                for key, value in self.algorithms.items():
                    print(f"{key}. {value}")
                
                algorithm = input("Choice: ")
                
                if algorithm == '4':  # RSA
                    public_key_path = input("Enter public key path: ")
                    self.encrypt_file(filepath, algorithm, public_key_path=public_key_path)
                else:
                    password = getpass("Enter password: ")
                    confirm = getpass("Confirm password: ")
                    
                    if password != confirm:
                        print(f"{Colors.FAIL}[!] Passwords do not match{Colors.ENDC}")
                        continue
                    
                    self.encrypt_file(filepath, algorithm, password)
            
            elif choice == '2':
                # Decrypt file
                filepath = input("Enter encrypted file path: ")
                if not os.path.exists(filepath):
                    print(f"{Colors.FAIL}[!] File not found{Colors.ENDC}")
                    continue
                
                # Check if it's RSA encrypted
                with open(filepath, 'rb') as f:
                    metadata_len = int.from_bytes(f.read(4), 'big')
                    metadata_json = f.read(metadata_len)
                    metadata = json.loads(metadata_json.decode())
                
                if metadata['algorithm'] == 'RSA-2048 (Asymmetric)':
                    private_key_path = input("Enter private key path: ")
                    key_password = getpass("Enter key password (if any): ") or None
                    self.decrypt_file(filepath, private_key_path=private_key_path, password=key_password)
                else:
                    password = getpass("Enter password: ")
                    self.decrypt_file(filepath, password)
            
            elif choice == '3':
                # Encrypt text
                text = input("Enter text to encrypt: ")
                
                print("\nSelect algorithm:")
                for key, value in self.algorithms.items():
                    print(f"{key}. {value}")
                
                algorithm = input("Choice: ")
                
                if algorithm == '4':  # RSA
                    public_key_path = input("Enter public key path: ")
                    encrypted = self.encrypt_text(text, algorithm, public_key_path=public_key_path)
                else:
                    password = getpass("Enter password: ")
                    encrypted = self.encrypt_text(text, algorithm, password)
                
                if encrypted:
                    print(f"\n{Colors.GREEN}Encrypted text:{Colors.ENDC}")
                    print(encrypted)
            
            elif choice == '4':
                # Decrypt text
                encrypted_text = input("Enter encrypted text (base64): ")
                
                print("\nSelect algorithm:")
                for key, value in self.algorithms.items():
                    print(f"{key}. {value}")
                
                algorithm = input("Choice: ")
                
                try:
                    if algorithm == '4':  # RSA
                        private_key_path = input("Enter private key path: ")
                        key_password = getpass("Enter key password (if any): ") or None
                        decrypted = self.decrypt_text(encrypted_text, algorithm, 
                                                    private_key_path=private_key_path, 
                                                    password=key_password)
                    else:
                        password = getpass("Enter password: ")
                        decrypted = self.decrypt_text(encrypted_text, algorithm, password)
                    
                    if decrypted:
                        print(f"\n{Colors.GREEN}Decrypted text:{Colors.ENDC}")
                        print(decrypted)
                except Exception as e:
                    print(f"{Colors.FAIL}[!] Decryption failed: {e}{Colors.ENDC}")
            
            elif choice == '5':
                # Generate RSA keys
                print("\n[*] Generating RSA-2048 key pair...")
                private_key, public_key = self.generate_rsa_keys()
                
                key_password = getpass("Enter password to protect private key (optional): ") or None
                self.save_rsa_keys(private_key, public_key, key_password)
            
            elif choice == '6':
                # Secure delete
                filepath = input("Enter file path to securely delete: ")
                if not os.path.exists(filepath):
                    print(f"{Colors.FAIL}[!] File not found{Colors.ENDC}")
                    continue
                
                confirm = input(f"{Colors.WARNING}Are you sure? This cannot be undone! (yes/no): {Colors.ENDC}")
                if confirm.lower() == 'yes':
                    passes = int(input("Number of overwrite passes (default 3): ") or "3")
                    self.secure_delete(filepath, passes)
            
            elif choice == '7':
                # Benchmark
                self.benchmark_algorithms()
            
            elif choice == '0':
                print(f"\n{Colors.GREEN}[*] Exiting...{Colors.ENDC}")
                break
            
            else:
                print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Encryption Tool - Secure file and text encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python encryption_tool.py                          # Interactive mode
  python encryption_tool.py -e file.txt -a aes-cbc   # Encrypt file
  python encryption_tool.py -d file.txt.enc          # Decrypt file
  python encryption_tool.py --generate-keys          # Generate RSA keys
  python encryption_tool.py --benchmark              # Benchmark algorithms
        """
    )
    
    parser.add_argument('-e', '--encrypt', metavar='FILE', help='Encrypt a file')
    parser.add_argument('-d', '--decrypt', metavar='FILE', help='Decrypt a file')
    parser.add_argument('-a', '--algorithm', choices=['aes-cbc', 'aes-gcm', 'fernet', 'rsa', 'chacha20'],
                       default='aes-cbc', help='Encryption algorithm')
    parser.add_argument('-p', '--password', help='Password (will prompt if not provided)')
    parser.add_argument('--public-key', help='Public key file for RSA encryption')
    parser.add_argument('--private-key', help='Private key file for RSA decryption')
    parser.add_argument('--generate-keys', action='store_true', help='Generate RSA key pair')
    parser.add_argument('--benchmark', action='store_true', help='Benchmark encryption algorithms')
    parser.add_argument('--secure-delete', metavar='FILE', help='Securely delete a file')
    
    args = parser.parse_args()
    
    tool = AdvancedEncryptionTool()
    tool.print_banner()
    
    # Map algorithm names
    alg_map = {
        'aes-cbc': '1',
        'aes-gcm': '2',
        'fernet': '3',
        'rsa': '4',
        'chacha20': '5'
    }
    
    # Handle command line arguments
    if args.generate_keys:
        print("[*] Generating RSA-2048 key pair...")
        private_key, public_key = tool.generate_rsa_keys()
        password = getpass("Enter password to protect private key (optional): ") or None
        tool.save_rsa_keys(private_key, public_key, password)
        
    elif args.benchmark:
        tool.benchmark_algorithms()
        
    elif args.secure_delete:
        if os.path.exists(args.secure_delete):
            confirm = input(f"{Colors.WARNING}Securely delete {args.secure_delete}? This cannot be undone! (yes/no): {Colors.ENDC}")
            if confirm.lower() == 'yes':
                tool.secure_delete(args.secure_delete)
        else:
            print(f"{Colors.FAIL}[!] File not found{Colors.ENDC}")
            
    elif args.encrypt:
        if not os.path.exists(args.encrypt):
            print(f"{Colors.FAIL}[!] File not found{Colors.ENDC}")
            sys.exit(1)
            
        algorithm = alg_map.get(args.algorithm)
        
        if args.algorithm == 'rsa':
            if not args.public_key:
                print(f"{Colors.FAIL}[!] Public key required for RSA encryption{Colors.ENDC}")
                sys.exit(1)
            tool.encrypt_file(args.encrypt, algorithm, public_key_path=args.public_key)
        else:
            password = args.password or getpass("Enter password: ")
            confirm = getpass("Confirm password: ")
            
            if password != confirm:
                print(f"{Colors.FAIL}[!] Passwords do not match{Colors.ENDC}")
                sys.exit(1)
                
            tool.encrypt_file(args.encrypt, algorithm, password)
            
    elif args.decrypt:
        if not os.path.exists(args.decrypt):
            print(f"{Colors.FAIL}[!] File not found{Colors.ENDC}")
            sys.exit(1)
            
        # Check metadata to determine if RSA
        try:
            with open(args.decrypt, 'rb') as f:
                metadata_len = int.from_bytes(f.read(4), 'big')
                metadata_json = f.read(metadata_len)
                metadata = json.loads(metadata_json.decode())
                
            if metadata['algorithm'] == 'RSA-2048 (Asymmetric)':
                if not args.private_key:
                    print(f"{Colors.FAIL}[!] Private key required for RSA decryption{Colors.ENDC}")
                    sys.exit(1)
                key_password = args.password or getpass("Enter key password (if any): ") or None
                tool.decrypt_file(args.decrypt, private_key_path=args.private_key, password=key_password)
            else:
                password = args.password or getpass("Enter password: ")
                tool.decrypt_file(args.decrypt, password)
                
        except Exception as e:
            print(f"{Colors.FAIL}[!] Failed to read file metadata: {e}{Colors.ENDC}")
            sys.exit(1)
    else:
        # Interactive mode
        tool.interactive_mode()


if __name__ == "__main__":
    main()
