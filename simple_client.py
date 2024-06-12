import socket
import ssl
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

# Server information
SERVER_HOST = '4cucbhwzzybh64eg4yjhrfjse4vbzgx6627fvra2whkm2maq3nvlefid.onion'
SERVER_PORT = 12345

# Encryption key and settings
password = b'mysecretpassword'
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(password)

def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = iv + encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    return encrypted_message

def decrypt_message(encrypted_message, key):
    iv = encrypted_message[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
    return decrypted_message.decode('utf-8')

def main():
    # Create an SSL context
    context = ssl.create_default_context()

    # Connect to the server
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:
            print(f"Connected to {SERVER_HOST}:{SERVER_PORT}")

            # Example message to send
            message = "Hello, secure server!"
            encrypted_message = encrypt_message(message, key)
            ssock.sendall(encrypted_message)

            # Receive response from server
            encrypted_response = ssock.recv(1024)
            response = decrypt_message(encrypted_response, key)
            print("Received:", response)

if __name__ == "__main__":
    main()
