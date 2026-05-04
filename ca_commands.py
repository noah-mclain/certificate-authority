import sys
import datetime
from getpass import getpass
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import padding

import ca_config, ca_utils, ca_db, ca_crypto, ca_core


def cmd_init(args):
    if ca_config.CA_CERT_FILE.exists():
        print("CA already initialized. Delete ca_data/ to reinitialize.")
        return
    for d in (ca_config.CA_DIR, ca_config.CERTS_DIR, ca_config.KEYS_DIR):
        d.mkdir(parents=True, exist_ok=True)

    ca_key = ca_crypto.generate_key(ca_config.CA_KEY_SIZE)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Simple CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Simple Root CA"),
        ]
    )
    now = ca_utils.utcnow()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=ca_config.CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    if args.ca_pass:
        passphrase = args.ca_pass
    else:
        passphrase = getpass("Enter passphrase to protect the CA private key: ")
        if getpass("Confirm passphrase: ") != passphrase:
            print("Error: Passphrases do not match.")
            sys.exit(1)
    ca_crypto.save_key(ca_key, ca_config.CA_KEY_FILE, passphrase=passphrase)
    ca_crypto.save_cert(ca_cert, ca_config.CA_CERT_FILE)
    ca_db.save_db({"certificates": []})
    print("Certificate Authority initialized successfully.")
    print(f"  CA Certificate : {ca_config.CA_CERT_FILE}")
    print(f"  CA Private Key : {ca_config.CA_KEY_FILE} (encrypted)")
    print(f"  Validity       : {ca_config.CA_VALIDITY_DAYS} days")


def cmd_issue(args):
    user_cert, user_key, serial = ca_core.issue_certificate(
        args.username, args.email, args.days, args.ca_pass
    )
    print(f"Certificate issued for '{args.username}' (serial #{serial})")
    print(f"  Certificate : {ca_config.CERTS_DIR / f'{args.username}_{serial}.pem'}")
    print(f"  Private Key : {ca_config.KEYS_DIR / f'{args.username}_{serial}_key.pem'}")
    print(
        f"  Valid Until : {(ca_utils.utcnow() + datetime.timedelta(days=args.days)).strftime('%Y-%m-%d')}"
    )


def cmd_revoke(args):
    ca_key, ca_cert = ca_crypto.load_ca(args.ca_pass)
    db = ca_db.load_db()
    target = next((e for e in db["certificates"] if e["serial"] == args.serial), None)
    if not target:
        print(f"Error: No certificate with serial #{args.serial}")
        sys.exit(1)
    if target["status"] == "revoked":
        print(f"Certificate #{args.serial} is already revoked.")
        return
    target["status"] = "revoked"
    target["revoked_at"] = ca_utils.utcnow().isoformat()

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(ca_utils.utcnow())
    builder = builder.next_update(
        ca_utils.utcnow() + datetime.timedelta(days=ca_config.CRL_UPDATE_DAYS)
    )
    for e in db["certificates"]:
        if e["status"] == "revoked":
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(e["serial"])
                .revocation_date(ca_utils.parse_iso_utc(e["revoked_at"]))
                .build()
            )
            builder = builder.add_revoked_certificate(revoked_cert)
    crl = builder.sign(ca_key, hashes.SHA256())
    with open(ca_config.CRL_FILE, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    ca_db.save_db(db)
    print(f"Certificate #{args.serial} ({target['username']}) has been revoked.")
    print(f"  CRL updated: {ca_config.CRL_FILE}")


def cmd_verify(args):
    # Only need the CA certificate, not the private key
    _, ca_cert = ca_crypto.load_ca(passphrase=args.ca_pass, load_key=False)
    db = ca_db.load_db()
    cert = ca_crypto.load_cert_from_file(args.cert_file)

    cn = "N/A"
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        pass
    print(f"Certificate: {cn}")
    print(f"Serial     : {cert.serial_number}\n")

    # Signature check
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        print("[PASS] Signature valid (signed by this CA)")
    except Exception:
        print("[FAIL] Signature invalid (not signed by this CA)")
        return

    # Validity period – use _utc variants to avoid deprecation
    now = ca_utils.utcnow()
    if cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        print(
            f"[PASS] Certificate is within validity period (expires {cert.not_valid_after_utc:%Y-%m-%d})"
        )
        days_left = (cert.not_valid_after_utc - now).days
        if days_left <= ca_config.CERT_EXPIRY_WARNING_DAYS:
            print(
                f"[WARN] Certificate expires in {days_left} day(s) – consider renewal!"
            )
    else:
        print(f"[FAIL] Certificate expired or not yet valid")

    # Revocation check
    for e in db["certificates"]:
        if e["serial"] == cert.serial_number:
            if e["status"] == "revoked":
                print(
                    f"[FAIL] Certificate has been REVOKED (on {e['revoked_at'][:10]})"
                )
            else:
                print("[PASS] Certificate is not revoked")
            return
    print("[WARN] Certificate not found in CA database")


def cmd_list(args):
    db = ca_db.load_db()
    if not db["certificates"]:
        print("No certificates issued yet.")
        return
    now = ca_utils.utcnow()
    print(
        f"{'Serial':<55} {'Username':<15} {'Status':<10} {'Issued':15} {'Expires':<12}"
    )
    print("-" * 110)
    for e in db["certificates"]:
        serial = e["serial"]
        username = e["username"]
        if e["status"] == "revoked":
            status_str = "\033[91mREVOKED\033[0m"
        else:
            exp = ca_utils.parse_iso_utc(e["expires"])
            if exp < now:
                status_str = "\033[93mEXPIRED\033[0m"
            else:
                status_str = "\033[92mVALID\033[0m  "
        print(
            f"#{serial:<55} {username:<15} {status_str:<18} {e['issued'][:10]:<15} {e['expires'][:10]:<12}"
        )


def cmd_info(args):
    cert = ca_crypto.load_cert_from_file(args.cert_file)
    print("=== Certificate Details ===")
    print(f"Subject       : {cert.subject.rfc4514_string()}")
    print(f"Issuer        : {cert.issuer.rfc4514_string()}")
    print(f"Serial        : {cert.serial_number}")
    print(f"Valid From    : {cert.not_valid_before_utc:%Y-%m-%d %H:%M:%S}")
    print(f"Valid Until   : {cert.not_valid_after_utc:%Y-%m-%d %H:%M:%S}")
    print(f"Signature Alg : {cert.signature_algorithm_oid._name}")
    print(f"Key Size      : {cert.public_key().key_size} bits")
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        print(f"Is CA         : {bc.value.ca}")
    except x509.ExtensionNotFound:
        pass
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        emails = san.value.get_values_for_type(x509.RFC822Name)
        if emails:
            print(f"Email (SAN)   : {', '.join(emails)}")
    except x509.ExtensionNotFound:
        pass


def cmd_renew(args):
    ca_key, ca_cert = ca_crypto.load_ca(args.ca_pass)
    db = ca_db.load_db()
    target = next((e for e in db["certificates"] if e["serial"] == args.serial), None)
    if not target:
        print(f"Error: No certificate with serial #{args.serial}")
        sys.exit(1)
    if target["status"] == "revoked":
        print(f"Error: Certificate #{args.serial} is already revoked – cannot renew.")
        sys.exit(1)

    # Revoke old cert
    target["status"] = "revoked"
    target["revoked_at"] = ca_utils.utcnow().isoformat()
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(ca_utils.utcnow())
    builder = builder.next_update(
        ca_utils.utcnow() + datetime.timedelta(days=ca_config.CRL_UPDATE_DAYS)
    )
    for e in db["certificates"]:
        if e["status"] == "revoked":
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(e["serial"])
                .revocation_date(ca_utils.parse_iso_utc(e["revoked_at"]))
                .build()
            )
            builder = builder.add_revoked_certificate(revoked_cert)
    crl = builder.sign(ca_key, hashes.SHA256())
    with open(ca_config.CRL_FILE, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    ca_db.save_db(db)

    new_days = args.days if hasattr(args, "days") else ca_config.CERT_VALIDITY_DAYS
    _, _, new_serial = ca_core.issue_certificate(
        target["username"], target["email"], new_days, args.ca_pass
    )
    print(f"Renewal complete – new certificate serial #{new_serial}")


def cmd_export(args):
    db = ca_db.load_db()
    target = next((e for e in db["certificates"] if e["serial"] == args.serial), None)
    if not target:
        print(f"Error: No certificate with serial #{args.serial}")
        sys.exit(1)
    if target["status"] == "revoked":
        print(f"Error: Certificate #{args.serial} is revoked – cannot export.")
        sys.exit(1)

    cert_path = Path(target["cert_file"])
    key_path = Path(target["key_file"])
    if not cert_path.exists() or not key_path.exists():
        print("Error: Certificate or key file missing.")
        sys.exit(1)

    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)

    if args.password:
        p12_pass = args.password
    else:
        p12_pass = getpass("Enter export password for the .p12 file: ")
        if getpass("Confirm export password: ") != p12_pass:
            print("Error: Passwords do not match.")
            sys.exit(1)

    p12 = pkcs12.serialize_key_and_certificates(
        name=target["username"].encode(),
        key=key,
        cert=cert,
        cas=[],
        encryption_algorithm=serialization.BestAvailableEncryption(p12_pass.encode()),
    )
    out_file = Path(f"{target['username']}_{args.serial}.p12")
    with open(out_file, "wb") as f:
        f.write(p12)
    print(f"PKCS#12 file exported: {out_file}")
