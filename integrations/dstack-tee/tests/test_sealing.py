import importlib.metadata
import json
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from eth_keys import keys
from eth_utils import keccak

from alpha_dstack_tee import AlphaDstackTEEPlugin


class SealingTests(unittest.TestCase):
    def setUp(self):
        self.signer = keys.PrivateKey(bytes.fromhex("11" * 32))
        self.recipient = X25519PrivateKey.generate()
        self.public_key = self.recipient.public_key().public_bytes_raw().hex()
        self.app = "ab" * 20
        self.pin = self.signer.public_key.to_compressed_bytes().hex()
        self.plugin = AlphaDstackTEEPlugin(self.pin)

    def reply(self, *, timestamp=None, app=None, signer=None):
        timestamp = int(time.time()) if timestamp is None else timestamp
        message = (b"dstack-env-encrypt-pubkey:" + bytes.fromhex(app or self.app)
                   + timestamp.to_bytes(8, "big") + bytes.fromhex(self.public_key))
        signature = (signer or self.signer).sign_msg_hash(keccak(message)).to_bytes().hex()
        return {"public_key": self.public_key, "signature_v1": signature, "timestamp": timestamp}

    def seal(self, reply=None, offered=None, app=None):
        return self.plugin.encrypt_environment(
            {"DATABASE_URL": "SYNTHETIC-ONLY"}, expected_app_id=app or self.app,
            offered_public_key=offered or self.public_key,
            signed_key=self.reply() if reply is None else reply)

    def assert_refused_before_encryption(self, **kwargs):
        with patch("alpha_dstack_tee.encrypt_env_vars_sync") as encrypt:
            with self.assertRaises(ValueError):
                self.seal(**kwargs)
            encrypt.assert_not_called()

    def test_registered_external_plugin(self):
        entry = next(iter(importlib.metadata.entry_points(
            group="alphacompute.integrations", name="dstack_tee")))
        self.assertIs(entry.load(), AlphaDstackTEEPlugin)

    def test_verified_ciphertext_interoperates_with_dependency_wire_format(self):
        data = bytes.fromhex(self.seal())
        shared = self.recipient.exchange(X25519PublicKey.from_public_bytes(data[:32]))
        result = json.loads(AESGCM(shared).decrypt(data[32:44], data[44:], None))
        self.assertEqual(result, {"env": [{"key": "DATABASE_URL", "value": "SYNTHETIC-ONLY"}]})

    def test_unsigned_and_legacy_only_keys_fail(self):
        for reply in ({"public_key": self.public_key},
                      {"public_key": self.public_key, "signature": "ab" * 65}):
            self.assert_refused_before_encryption(reply=reply)

    def test_substituted_offered_key_fails(self):
        self.assert_refused_before_encryption(offered="01" * 32)

    def test_wrong_signer_fails(self):
        self.assert_refused_before_encryption(
            reply=self.reply(signer=keys.PrivateKey(bytes.fromhex("22" * 32))))

    def test_signature_for_another_app_fails(self):
        self.assert_refused_before_encryption(reply=self.reply(app="cd" * 20))

    def test_expired_and_future_signatures_fail(self):
        for offset in (-301, 61):
            self.assert_refused_before_encryption(reply=self.reply(timestamp=int(time.time()) + offset))

    def test_timestamp_types_and_bounds_fail(self):
        for timestamp in (True, "1", -1, 2**64):
            self.assert_refused_before_encryption(reply={**self.reply(), "timestamp": timestamp})

    def test_malformed_key_and_signature_fail(self):
        for field, value in (("public_key", "01"), ("signature_v1", "xyz")):
            self.assert_refused_before_encryption(reply={**self.reply(), field: value})

    def test_pin_is_mandatory_and_age_cannot_disable_freshness(self):
        for pin in ("", "ab", "04" + "00" * 32):
            with self.assertRaises(ValueError):
                AlphaDstackTEEPlugin(pin)
        for age in (0, 301, True):
            with self.assertRaises(ValueError):
                AlphaDstackTEEPlugin(self.pin, age)

    def test_invalid_values_are_not_echoed(self):
        with self.assertRaises(ValueError) as error:
            self.plugin.encrypt_environment({"INVALID-NAME": "PRIVATE"}, expected_app_id=self.app,
                offered_public_key=self.public_key, signed_key=self.reply())
        self.assertNotIn("PRIVATE", str(error.exception))


if __name__ == "__main__":
    unittest.main()
