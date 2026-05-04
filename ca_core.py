import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import ca_config, ca_utils, ca_db, ca_crypto

def issue_certificate(
    username: str,
    email: str = None,
    days: int = ca_config.CERT_VALIDITY_DAYS,
    ca_pass: str = None,
):
    ca_key, ca_cert = ca_crypto.load_ca(ca_pass)
    db = ca_db.load_db()
    serial = x509.random_serial_number()
    user_key = ca_crypto.generate_key()

    name_attrs = [
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Simple CA"),
    ]
    if email:
        name_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

    subject = x509.Name(name_attrs)
    now = ca_utils.utcnow()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ), critical=True,
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
    if email:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(email)]),
            critical=False,
        )

    user_cert = builder.sign(ca_key, hashes.SHA256())

    cert_file = ca_config.CERTS_DIR / f"{username}_{serial}.pem"
    key_file = ca_config.KEYS_DIR / f"{username}_{serial}_key.pem"
    cert_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.parent.mkdir(parents=True, exist_ok=True)

    ca_crypto.save_cert(user_cert, cert_file)
    ca_crypto.save_key(user_key, key_file)

    db["certificates"].append({
        "serial": serial,
        "username": username,
        "email": email or "",
        "issued": now.isoformat(),
        "expires": (now + datetime.timedelta(days=days)).isoformat(),
        "status": "valid",
        "cert_file": str(cert_file),
        "key_file": str(key_file),
    })
    ca_db.save_db(db)
    return user_cert, user_key, serial