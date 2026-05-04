# Simple Certificate Authority (CA)

A modular, educational X.509 Certificate Authority written in Python. It can initialize a root CA, issue user certificates, revoke them, verify certificates, and export to PKCS#12 (`.p12`) format. The CA private key is encrypted with a passphrase, and the database is stored atomically to prevent corruption.

## Requirements

- Python 3.8+ (tested on 3.11)
- [cryptography](https://cryptography.io) library (`pip install cryptography`)

## File Structure

```text
.
├── ca.py                 # Entry point
├── ca_cli.py             # CLI argument parsing and dispatch
├── ca_commands.py        # Implementation of each command (init, issue, revoke, etc.)
├── ca_core.py            # Core certificate issuance logic
├── ca_crypto.py          # Key/certificate I/O and CA loading
├── ca_db.py              # Database (JSON) load/save with atomic writes
├── ca_utils.py           # Time helpers (UTC, ISO parsing)
├── ca_config.py          # Paths and constants
├── test_ca.py            # Test suite
└── README.md
```

All data (CA key, certs, database, CRL) is stored inside a `ca_data/` directory created next to the script.

## Quick Start

```bash
# Install dependencies
pip install cryptography

# Initialize a new CA (you will be prompted for a CA passphrase)
python ca.py init

# Issue a certificate
python ca.py issue alice --email alice@example.com --days 365

# List all certificates
python ca.py list

# Verify a certificate
python ca.py verify ca_data/certs/alice_<serial>.pem

# Show certificate details
python ca.py info ca_data/certs/alice_<serial>.pem

# Revoke a certificate by serial
python ca.py revoke <serial>

# Renew (revoke old + issue new)
python ca.py renew <serial> --days 30

# Export to PKCS#12 (browser‑importable)
python ca.py export --serial <serial> --password p12password
```

## Commands

### `init`

Initializes the CA: generates a 4096‑bit RSA root key (encrypted with a passphrase) and a self‑signed root certificate valid for 10 years. The database and directory structure are created under `ca_data/`.

```bash
python ca.py init
# or pass the passphrase directly (non‑interactive)
python ca.py init --ca-pass mySecretPass
```

### `issue`

Issues a new user certificate signed by the CA. The user’s private key is **not** encrypted by default (you may want to protect it separately). A random 20‑byte serial number is assigned.

```bash
python ca.py issue <username> [--email EMAIL] [--days DAYS]
```

Example:

```bash
python ca.py issue alice --email alice@example.com --days 365
```

The certificate and key are saved as `ca_data/certs/<username>_<serial>.pem` and `ca_data/private_keys/<username>_<serial>_key.pem`.

### `revoke`

Revokes a certificate by serial number and updates the Certificate Revocation List (CRL).

```bash
python ca.py revoke <serial>
```

### `verify`

Verifies a certificate against the CA. Checks:

- Signature validity
- Expiration (warns if expiring within 30 days)
- Revocation status

```bash
python ca.py verify <path_to_cert.pem>
```

### `list`

Displays a table of all issued certificates with their status (VALID, EXPIRED, REVOKED).

```bash
python ca.py list
```

### `info`

Prints detailed information about a certificate: subject, issuer, serial, validity, key size, extensions.

```bash
python ca.py info <path_to_cert.pem>
```

### `renew`

Revokes the old certificate and immediately issues a new one with the same username and email. You can override the validity period.

```bash
python ca.py renew <serial> [--days DAYS]
```

### `export`

Exports the certificate and corresponding private key into an encrypted PKCS#12 file (`.p12`). This is the standard format for importing into browsers and operating system keystores.

```bash
python ca.py export --serial <serial> [--password P12_PASS]
```

If `--password` is omitted, you are prompted interactively.

## Testing

The test suite uses `unittest` and `tempfile` – no external test dependencies are needed.

```bash
# Run all tests
python test_ca.py

# Run with more verbose output
python test_ca.py -v
```

Tests cover:

- CA initialization with passphrase encryption
- Issuing certificates
- Verification (signature, expiry warning, revoked cert, missing file)
- Revocation and CRL generation
- Renewal (revoke + issue)
- PKCS#12 export
- Atomic database writes
- Friendly error on missing file
- Expiry warning

## Security Notes

- **CA private key** is always encrypted at rest. Never store the passphrase in scripts.
- User private keys are generated **without** passphrases by default – protect them accordingly.
- The serial numbers are cryptographically random (20 bytes) to prevent enumeration.
- The database is written atomically (write to `.tmp` → rename) to avoid corruption.
- This is an **educational tool** and should not be used in production without further hardening.

## License

This project is provided for educational purposes. Use at your own risk.

## Submitted By

- Zeina Ahmed — 221017888
- Malak Maher — 221027544
- Nada Ayman — 221007645
