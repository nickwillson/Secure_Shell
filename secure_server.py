import socket  # Import the socket module for networking.
import os  # Import the OS module.
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Import necessary modules for AES encryption.
from cryptography.hazmat.primitives.asymmetric import padding  # Import padding module for RSA.
from cryptography.hazmat.primitives import hashes, serialization  # Import hashes and serialization modules.

# Load RSA private key
with open("private_key.pem", "rb") as key_file:  # Open the private key file in read-binary mode.
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

def decrypt_rsa(encrypted_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_message(encrypted_message, key, iv):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.CFB(iv),
    ).decryptor()
    return decryptor.update(encrypted_message) + decryptor.finalize()

def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP/IP socket.
    server_socket.bind(('127.0.0.1', 12345))  # Bind the socket to the local host and port 12345.
    server_socket.listen(1)  # Listen for incoming connections.
    print("Server is listening on port 12345")
    
    while True:
        client_socket, client_address = server_socket.accept()  # Wait for a connection.
        print(f"Connection from {client_address}")

        # Receive encrypted symmetric key
        encrypted_key = client_socket.recv(256)  # Receive the encrypted symmetric key.
        key = decrypt_rsa(encrypted_key)  # Decrypt the symmetric key.
        
        # Receive IV
        iv = client_socket.recv(16)  # Receive the initialization vector (IV).
        
        # Receive encrypted message
        encrypted_message = client_socket.recv(1024)  # Receive the encrypted message.
        
        # Decrypt message
        message = decrypt_message(encrypted_message, key, iv)  # Decrypt the message.
        print(f"Received encrypted data: {encrypted_message}")
        print(f"Decrypted message: {message.decode()}")

        response = b'Hello from the secure server!'  # Prepare a response message.
        client_socket.sendall(response)  # Send the response message.
        client_socket.close()  # Close the connection.

if __name__ == "__main__":
    run_server()  # Run the server if this script is executed directly.
