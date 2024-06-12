from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537,  # This is a common public exponent used in RSA.
    key_size=2048,  # Key size of 2048 bits.
)

public_key = private_key.public_key()  # Extract the public key from the private key.

# Save the private key
with open("private_key.pem", "wb") as f:  # Open a file to write the private key in binary mode.
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,  # Encode the key in PEM format.
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # Use the traditional OpenSSL format.
        encryption_algorithm=serialization.NoEncryption(),  # No encryption for the private key.
    ))

# Save the public key
with open("public_key.pem", "wb") as f:  # Open a file to write the public key in binary mode.
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,  # Encode the key in PEM format.
        format=serialization.PublicFormat.SubjectPublicKeyInfo,  # Use the SubjectPublicKeyInfo format.
    ))
