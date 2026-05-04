#!/usr/bin/env python3
import unittest
import argparse
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import timedelta, timezone
import datetime

import sys

sys.path.insert(0, str(Path(__file__).parent))

import ca_config
import ca_utils
import ca_db
import ca_crypto
import ca_core
import ca_commands

TEST_CA_PASS = "testpass"


class TestCA(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        base = Path(self.temp_dir.name)
        ca_config.CA_DIR = base / "ca_data"
        ca_config.CA_KEY_FILE = ca_config.CA_DIR / "ca_key.pem"
        ca_config.CA_CERT_FILE = ca_config.CA_DIR / "ca_cert.pem"
        ca_config.CERTS_DIR = ca_config.CA_DIR / "certs"
        ca_config.KEYS_DIR = ca_config.CA_DIR / "private_keys"
        ca_config.DB_FILE = ca_config.CA_DIR / "ca_database.json"
        ca_config.CRL_FILE = ca_config.CA_DIR / "crl.pem"
        if ca_config.CA_DIR.exists():
            shutil.rmtree(ca_config.CA_DIR, ignore_errors=True)
        self._init_ca()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _init_ca(self):
        ca_commands.cmd_init(argparse.Namespace(ca_pass=TEST_CA_PASS))

    def test_init_and_issue(self):
        cert, key, serial = ca_core.issue_certificate(
            "alice", "alice@example.com", 365, ca_pass=TEST_CA_PASS
        )
        self.assertIsNotNone(cert)
        db = ca_db.load_db()
        self.assertEqual(len(db["certificates"]), 1)
        self.assertEqual(db["certificates"][0]["serial"], serial)

    def test_verify(self):
        cert, key, serial = ca_core.issue_certificate(
            "bob", "bob@test.com", 365, ca_pass=TEST_CA_PASS
        )
        cert_file = ca_config.CERTS_DIR / f"bob_{serial}.pem"
        # Successful verification (passphrase provided via ca_pass)
        ca_commands.cmd_verify(
            argparse.Namespace(cert_file=str(cert_file), ca_pass=TEST_CA_PASS)
        )
        # Missing file causes SystemExit
        with self.assertRaises(SystemExit):
            ca_commands.cmd_verify(
                argparse.Namespace(cert_file="nonexistent.pem", ca_pass=TEST_CA_PASS)
            )

    def test_revoke_and_crl(self):
        cert, key, serial = ca_core.issue_certificate(
            "carol", days=30, ca_pass=TEST_CA_PASS
        )
        ca_commands.cmd_revoke(argparse.Namespace(serial=serial, ca_pass=TEST_CA_PASS))
        db = ca_db.load_db()
        self.assertEqual(db["certificates"][0]["status"], "revoked")
        self.assertTrue(ca_config.CRL_FILE.exists())

    def test_renew(self):
        cert, key, serial = ca_core.issue_certificate(
            "dave", days=7, ca_pass=TEST_CA_PASS
        )
        ca_commands.cmd_renew(
            argparse.Namespace(serial=serial, ca_pass=TEST_CA_PASS, days=30)
        )
        db = ca_db.load_db()
        self.assertEqual(len(db["certificates"]), 2)
        self.assertEqual(db["certificates"][0]["status"], "revoked")
        self.assertEqual(db["certificates"][1]["status"], "valid")

    def test_export_pkcs12(self):
        cert, key, serial = ca_core.issue_certificate(
            "eve", days=30, ca_pass=TEST_CA_PASS
        )
        ca_commands.cmd_export(argparse.Namespace(serial=serial, password="exportpass"))
        p12_file = Path(f"eve_{serial}.p12")
        self.assertTrue(p12_file.exists())
        p12_file.unlink()

    def test_atomic_save_and_load_db(self):
        db = ca_db.load_db()
        db["certificates"].append({"serial": 1, "username": "test"})
        ca_db.save_db(db)
        loaded = ca_db.load_db()
        self.assertEqual(loaded["certificates"][-1]["username"], "test")

    def test_friendly_file_not_found(self):
        with self.assertRaises(SystemExit):
            ca_commands.cmd_verify(
                argparse.Namespace(cert_file="no_such_file.pem", ca_pass=TEST_CA_PASS)
            )

    @patch("ca_utils.utcnow")
    @patch("ca_db.load_db")
    def test_expiry_warning(self, mock_db, mock_utcnow):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes

        # Mock the CA certificate so that signature verification
        # automatically succeeds without needing a real key.
        mock_ca_cert = MagicMock()
        mock_ca_cert.subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Simple Root CA")]
        )
        mock_pubkey = MagicMock()
        mock_pubkey.verify = MagicMock()  # no-op (success)
        mock_ca_cert.public_key.return_value = mock_pubkey

        with patch("ca_crypto.load_ca", return_value=(None, mock_ca_cert)):
            now = datetime.datetime.now(timezone.utc)
            mock_utcnow.return_value = now

            # Build a fake user certificate that expires in 20 days
            key = ca_crypto.generate_key()
            fake_cert = (
                x509.CertificateBuilder()
                .subject_name(
                    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
                )
                .issuer_name(mock_ca_cert.subject)  # matches the mocked CA
                .public_key(key.public_key())
                .serial_number(999)
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=20))  # soon to expire
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None), critical=True
                )
                .sign(key, hashes.SHA256())  # signature doesn't matter now
            )

            with patch("ca_crypto.load_cert_from_file", return_value=fake_cert):
                mock_db.return_value = {
                    "certificates": [{"serial": 999, "status": "valid"}]
                }
                with patch("builtins.print") as mock_print:
                    ca_commands.cmd_verify(
                        argparse.Namespace(cert_file="dummy.pem", ca_pass=TEST_CA_PASS)
                    )
                    found = any(
                        "WARN" in str(args[0]) for args, _ in mock_print.call_args_list
                    )
                    self.assertTrue(found, "Expiry warning not printed")


if __name__ == "__main__":
    unittest.main()
