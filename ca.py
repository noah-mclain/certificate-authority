#!/usr/bin/env python3
"""
Simple Certificate Authority (CA)
Issues and manages X.509 digital certificates for users.

Usage:
    python ca.py init                              Initialize the CA
    python ca.py issue <username> [--email EMAIL]  Issue a certificate
    python ca.py revoke <serial>                   Revoke a certificate
    python ca.py verify <cert_file>                Verify a certificate
    python ca.py list                              List all certificates
    python ca.py info <cert_file>                  Show certificate details
"""

import argparse
import datetime
import json
import os
import sys
import warnings
from pathlib import Path

from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

CA_DIR = Path(__file__).parent / "ca_data"
CA_KEY_FILE = CA_DIR / "ca_key.pem"
CA_CERT_FILE = CA_DIR / "ca_cert.pem"
CERTS_DIR = CA_DIR / "certs"
KEYS_DIR = CA_DIR / "private_keys"
DB_FILE = CA_DIR / "ca_database.json"
CRL_FILE = CA_DIR / "crl.pem"

CERT_VALIDITY_DAYS = 365
CA_VALIDITY_DAYS = 3650


def load_db():
    if DB_FILE.exists():
        with open(DB_FILE) as f:
            return json.load(f)
    return {"next_serial": 1, "certificates": []}


def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)


def generate_key(bits=2048):
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend(),
    )


def save_key(key, path, passphrase=None):
    enc = serialization.NoEncryption()
    if passphrase:
        enc = serialization.BestAvailableEncryption(passphrase.encode())
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=enc,
        ))


def save_cert(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def load_ca():
    if not CA_KEY_FILE.exists() or not CA_CERT_FILE.exists():
        print("Error: CA not initialized. Run 'python ca.py init' first.")
        sys.exit(1)
    with open(CA_KEY_FILE, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(CA_CERT_FILE, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    return ca_key, ca_cert


# ── Commands ──────────────────────────────────────────────────────────

def cmd_init(args):
    if CA_CERT_FILE.exists():
        print("CA already initialized. Delete ca_data/ to reinitialize.")
        return

    for d in [CA_DIR, CERTS_DIR, KEYS_DIR]:
        d.mkdir(parents=True, exist_ok=True)

    ca_key = generate_key(4096)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Simple CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Simple Root CA"),
    ])

    now = datetime.datetime.utcnow()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    save_key(ca_key, CA_KEY_FILE)
    save_cert(ca_cert, CA_CERT_FILE)
    save_db({"next_serial": 1, "certificates": []})

    print("Certificate Authority initialized successfully.")
    print(f"  CA Certificate : {CA_CERT_FILE}")
    print(f"  CA Private Key : {CA_KEY_FILE}")
    print(f"  Validity       : {CA_VALIDITY_DAYS} days ({CA_VALIDITY_DAYS // 365} years)")


def cmd_issue(args):
    ca_key, ca_cert = load_ca()
    db = load_db()

    serial = db["next_serial"]
    user_key = generate_key()

    name_attrs = [
        x509.NameAttribute(NameOID.COMMON_NAME, args.username),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Simple CA"),
    ]
    if args.email:
        name_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, args.email))

    subject = x509.Name(name_attrs)
    now = datetime.datetime.utcnow()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(user_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )

    if args.email:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(args.email)]),
            critical=False,
        )

    user_cert = builder.sign(ca_key, hashes.SHA256(), default_backend())

    cert_file = CERTS_DIR / f"{args.username}_{serial}.pem"
    key_file = KEYS_DIR / f"{args.username}_{serial}_key.pem"
    save_cert(user_cert, cert_file)
    save_key(user_key, key_file)

    db["next_serial"] = serial + 1
    db["certificates"].append({
        "serial": serial,
        "username": args.username,
        "email": args.email or "",
        "issued": now.isoformat(),
        "expires": (now + datetime.timedelta(days=CERT_VALIDITY_DAYS)).isoformat(),
        "status": "valid",
        "cert_file": str(cert_file),
        "key_file": str(key_file),
    })
    save_db(db)

    print(f"Certificate issued for '{args.username}' (serial #{serial})")
    print(f"  Certificate : {cert_file}")
    print(f"  Private Key : {key_file}")
    print(f"  Valid Until : {now + datetime.timedelta(days=CERT_VALIDITY_DAYS):%Y-%m-%d}")


def cmd_revoke(args):
    ca_key, ca_cert = load_ca()
    db = load_db()

    target = None
    for entry in db["certificates"]:
        if entry["serial"] == args.serial:
            target = entry
            break

    if not target:
        print(f"Error: No certificate with serial #{args.serial}")
        sys.exit(1)

    if target["status"] == "revoked":
        print(f"Certificate #{args.serial} is already revoked.")
        return

    target["status"] = "revoked"
    target["revoked_at"] = datetime.datetime.utcnow().isoformat()

    # Rebuild CRL with all revoked certs
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(datetime.datetime.utcnow())
    builder = builder.next_update(datetime.datetime.utcnow() + datetime.timedelta(days=30))

    for entry in db["certificates"]:
        if entry["status"] == "revoked":
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(entry["serial"])
                .revocation_date(datetime.datetime.fromisoformat(entry["revoked_at"]))
                .build(default_backend())
            )
            builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(ca_key, hashes.SHA256(), default_backend())
    with open(CRL_FILE, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

    save_db(db)
    print(f"Certificate #{args.serial} ({target['username']}) has been revoked.")
    print(f"  CRL updated: {CRL_FILE}")


def cmd_verify(args):
    ca_key, ca_cert = load_ca()
    db = load_db()

    with open(args.cert_file, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    print(f"Certificate: {cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print(f"Serial     : {cert.serial_number}")
    print()

    # Check signature
    try:
        ca_key_pub = ca_cert.public_key()
        ca_key_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        print("[PASS] Signature valid (signed by this CA)")
    except Exception:
        print("[FAIL] Signature invalid (not signed by this CA)")
        return

    # Check expiry
    now = datetime.datetime.utcnow()
    if cert.not_valid_before <= now <= cert.not_valid_after:
        print(f"[PASS] Certificate is within validity period (expires {cert.not_valid_after:%Y-%m-%d})")
    else:
        print(f"[FAIL] Certificate expired or not yet valid")

    # Check revocation
    for entry in db["certificates"]:
        if entry["serial"] == cert.serial_number:
            if entry["status"] == "revoked":
                print(f"[FAIL] Certificate has been REVOKED (on {entry['revoked_at'][:10]})")
            else:
                print("[PASS] Certificate is not revoked")
            return

    print("[WARN] Certificate not found in CA database")


def cmd_list(args):
    db = load_db()

    if not db["certificates"]:
        print("No certificates issued yet.")
        return

    print(f"{'Serial':<8} {'Username':<20} {'Status':<10} {'Issued':<12} {'Expires':<12}")
    print("-" * 62)
    for entry in db["certificates"]:
        status = entry["status"].upper()
        if status == "REVOKED":
            status = "\033[91mREVOKED\033[0m"
        elif status == "VALID":
            exp = datetime.datetime.fromisoformat(entry["expires"])
            if exp < datetime.datetime.utcnow():
                status = "\033[93mEXPIRED\033[0m"
            else:
                status = "\033[92mVALID\033[0m  "
        print(
            f"#{entry['serial']:<7} {entry['username']:<20} {status:<10} "
            f"{entry['issued'][:10]:<12} {entry['expires'][:10]:<12}"
        )


def cmd_info(args):
    with open(args.cert_file, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    print("=== Certificate Details ===")
    print(f"Subject      : {cert.subject.rfc4514_string()}")
    print(f"Issuer       : {cert.issuer.rfc4514_string()}")
    print(f"Serial       : {cert.serial_number}")
    print(f"Valid From   : {cert.not_valid_before:%Y-%m-%d %H:%M:%S}")
    print(f"Valid Until   : {cert.not_valid_after:%Y-%m-%d %H:%M:%S}")
    print(f"Signature Alg: {cert.signature_algorithm_oid._name}")
    print(f"Key Size     : {cert.public_key().key_size} bits")

    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        print(f"Is CA        : {bc.value.ca}")
    except x509.ExtensionNotFound:
        pass

    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        emails = san.value.get_values_for_type(x509.RFC822Name)
        if emails:
            print(f"Email (SAN)  : {', '.join(emails)}")
    except x509.ExtensionNotFound:
        pass


# ── CLI ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Simple Certificate Authority")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="Initialize the CA (generate root cert & key)")

    p_issue = sub.add_parser("issue", help="Issue a certificate for a user")
    p_issue.add_argument("username", help="Username / Common Name")
    p_issue.add_argument("--email", help="Email address to embed in the certificate")

    p_revoke = sub.add_parser("revoke", help="Revoke a certificate by serial number")
    p_revoke.add_argument("serial", type=int, help="Certificate serial number")

    p_verify = sub.add_parser("verify", help="Verify a certificate against the CA")
    p_verify.add_argument("cert_file", help="Path to the PEM certificate file")

    sub.add_parser("list", help="List all issued certificates")

    p_info = sub.add_parser("info", help="Show certificate details")
    p_info.add_argument("cert_file", help="Path to the PEM certificate file")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "init": cmd_init,
        "issue": cmd_issue,
        "revoke": cmd_revoke,
        "verify": cmd_verify,
        "list": cmd_list,
        "info": cmd_info,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
