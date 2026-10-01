import base64
import hashlib
import unittest

from icp import tls


class AppleRootPin(unittest.TestCase):
    def test_bundled_root_matches_pin(self):
        pem = tls.apple_root_pem()
        body = b"".join(l.strip() for l in pem.splitlines() if l.strip() and not l.startswith(b"-----"))
        self.assertEqual(hashlib.sha256(base64.b64decode(body)).hexdigest(), tls.APPLE_ROOT_CA_SHA256)

    def test_tampered_root_is_refused(self):
        real = tls.APPLE_ROOT_CA_SHA256
        try:
            tls.APPLE_ROOT_CA_SHA256 = "00" * 32
            with self.assertRaises(tls.TLSBundleError):
                tls.apple_root_pem()
        finally:
            tls.APPLE_ROOT_CA_SHA256 = real

    def test_env_override_wins(self):
        import os
        os.environ["ICP_CA_BUNDLE"] = "/nonexistent/custom.pem"
        try:
            self.assertEqual(tls.ca_bundle(), "/nonexistent/custom.pem")
        finally:
            del os.environ["ICP_CA_BUNDLE"]
