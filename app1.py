import os
import sys
import argparse
from hashlib import sha256
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str) -> bytes:
    """
    Derive a 256-bit key from the password string using SHA-256.
    """
    return sha256(password.encode('utf-8')).digest()

def encrypt_file(input_path: str, output_path: str, password: str):
    """
    Encrypt the input file with AES-CBC, prepend the IV to output file.
    """
    key = derive_key(password)
    iv = os.urandom(16)

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # PKCS7 padding to block size 128 bits (16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    with open(output_path, 'wb') as f:
        # prepend IV
        f.write(iv + ciphertext)
    print(f"File encrypted successfully: {output_path}")

def decrypt_file(input_path: str, output_path: str, password: str):
    """
    Decrypt the input file with AES-CBC, assumes IV is prepended.
    """
    key = derive_key(password)

    with open(input_path, 'rb') as f:
        data = f.read()

    if len(data) < 16:
        print("Error: Input file is too short to contain IV.")
        sys.exit(1)

    iv = data[:16]
    ciphertext = data[16:]

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    try:
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    except ValueError:
        print("Decryption failed: Incorrect password or corrupted file.")
        sys.exit(1)

    with open(output_path, 'wb') as f:
        f.write(plaintext)
    print(f"File decrypted successfully: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="AES file encryptor/decryptor using AES-CBC with SHA-256 key derivation")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help="Mode: encrypt or decrypt")
    parser.add_argument('-i', '--input', required=True, help="Input file path")
    parser.add_argument('-o', '--output', required=False, help="Output file path (optional)")
    parser.add_argument('-k', '--key', required=True, help="Encryption/decryption key (password)")

    args = parser.parse_args()

    input_path = args.input
    if args.output:
        output_path = args.output
    else:
        if args.mode == 'encrypt':
            output_path = input_path + '.aes'
        else:
            if input_path.lower().endswith('.aes'):
                output_path = input_path[:-4]
            else:
                output_path = input_path + '.decrypted'

    if args.mode == 'encrypt':
        encrypt_file(input_path, output_path, args.key)
    else:
        decrypt_file(input_path, output_path, args.key)

if __name__ == '__main__':
    main()

