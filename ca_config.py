from pathlib import Path

CA_DIR = Path(__file__).parent / "ca_data"
CA_KEY_FILE = CA_DIR / "ca_key.pem"
CA_CERT_FILE = CA_DIR / "ca_cert.pem"
CERTS_DIR = CA_DIR / "certs"
KEYS_DIR = CA_DIR / "private_keys"
DB_FILE = CA_DIR / "ca_database.json"
CRL_FILE = CA_DIR / "crl.pem"

CERT_VALIDITY_DAYS = 365
CA_VALIDITY_DAYS = 3650
CRL_UPDATE_DAYS = 30
CERT_EXPIRY_WARNING_DAYS = 30

DEFAULT_USER_KEY_SIZE = 2048
CA_KEY_SIZE = 4096
