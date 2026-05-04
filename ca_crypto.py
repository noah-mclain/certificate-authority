import sys
from getpass import getpass
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
import ca_config


def generate_key(key_size: int = ca_config.DEFAULT_USER_KEY_SIZE):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def save_key(key, path, passphrase=None):
    enc = serialization.NoEncryption()
    if passphrase:
        enc = serialization.BestAvailableEncryption(passphrase.encode())
    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=enc,
            )
        )


def save_cert(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def load_cert_from_file(path_str: str):
    path = Path(path_str)
    if not path.exists():
        print(f"Error: File not found: {path_str}")
        sys.exit(1)
    try:
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())
    except Exception as e:
        print(f"Error: Could not load certificate from {path_str}: {e}")
        sys.exit(1)


def load_ca(passphrase=None, load_key=True):
    """
    Load the CA certificate and (optionally) private key.
    If load_key is False, only the certificate is returned (key=None).
    """
    if not ca_config.CA_KEY_FILE.exists() or not ca_config.CA_CERT_FILE.exists():
        print("Error: CA not initialized. Run 'python ca.py init' first.")
        sys.exit(1)

    with open(ca_config.CA_CERT_FILE, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    if not load_key:
        return None, ca_cert

    # Load private key (may be encrypted)
    try:
        with open(ca_config.CA_KEY_FILE, "rb") as f:
            key_data = f.read()
        ca_key = serialization.load_pem_private_key(key_data, password=None)
    except TypeError:
        if not passphrase:
            passphrase = getpass("Enter CA private key passphrase: ")
        with open(ca_config.CA_KEY_FILE, "rb") as f:
            ca_key = serialization.load_pem_private_key(
                f.read(), password=passphrase.encode()
            )
    return ca_key, ca_cert
