"""Regression checks of the actual deployment helper with signed synthetic keys."""
import hashlib
import importlib.util
import json
from pathlib import Path
import time
import unittest
from unittest.mock import patch, mock_open

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from eth_keys import keys
from eth_utils import keccak

source = Path(__file__).resolve().parents[1] / 'phala.py'
spec = importlib.util.spec_from_file_location('reviewed_phala', source)
phala = importlib.util.module_from_spec(spec)
spec.loader.exec_module(phala)

class PhalaEnvChecks(unittest.TestCase):
    def exercise(self, action, case):
        recipient = X25519PrivateKey.generate()
        public_key = recipient.public_key().public_bytes_raw().hex()
        signer = keys.PrivateKey(bytes.fromhex('11' * 32))
        app = 'ab' * 20
        timestamp = int(time.time()) + {'stale': -301, 'future': 61}.get(case, 0)
        signed_app = 'cd' * 20 if case == 'wrong-app' else app
        message = b'dstack-env-encrypt-pubkey:' + bytes.fromhex(signed_app) + timestamp.to_bytes(8, 'big') + bytes.fromhex(public_key)
        signature = signer.sign_msg_hash(keccak(message)).to_bytes().hex()
        signed = {'public_key': public_key, 'timestamp': timestamp, 'signature_v1': signature}
        if case == 'unsigned': signed.pop('signature_v1')
        offered = '01' * 32 if case == 'substituted' else public_key
        compose = b'{"allowed_envs":["ALPHACOMPUTE_DATABASE_URL"]}'
        digest = hashlib.sha256(compose).hexdigest()
        commits = []
        calls = []
        def fake_call(method, path, body=None):
            calls.append((method, path))
            if path.endswith('/provision'):
                return {'compose_hash': digest, 'app_id': app, 'app_env_encrypt_pubkey': offered, 'kms_id': 'test-kms'}
            if path == '/kms/test-kms/pubkey/' + app: return signed
            if method == 'GET' and path == '/cvms/existing':
                return {'app_id': app, 'kms_type': 'test-kms', 'kms_info': {'encrypted_env_pubkey': offered}}
            if path == '/cvms' or method == 'PATCH':
                commits.append(body)
                return {'id': 'synthetic-cvm'}
            raise AssertionError((method, path))
        pin = signer.public_key.to_compressed_bytes().hex()
        if case == 'missing-pin': pin = ''
        if case == 'wrong-pin': pin = keys.PrivateKey(bytes.fromhex('22' * 32)).public_key.to_compressed_bytes().hex()
        with patch('builtins.open', mock_open(read_data=compose)):
            argv = ['phala.py', 'create', 'compose.json', 'synthetic'] if action == 'create' else ['phala.py', 'update', 'existing', 'compose.json']
            with patch.object(phala, 'call', fake_call), patch.object(phala, 'check_stored'), patch.object(phala, 'report'), \
                 patch.object(phala.sys, 'argv', argv), patch.dict(phala.os.environ, {'PHALA_KMS_SIGNER': pin, 'ALPHACOMPUTE_DATABASE_URL': 'postgres://SYNTHETIC-ONLY'}):
                if case == 'valid': phala.main()
                else:
                    with self.assertRaises(ValueError): phala.main()
        if case != 'valid':
            self.assertEqual(commits, [])
            if case == 'missing-pin': self.assertEqual(calls, [])
            return
        self.assertEqual(len(commits), 1)
        blob = bytes.fromhex(commits[0]['encrypted_env'])
        shared = recipient.exchange(X25519PublicKey.from_public_bytes(blob[:32]))
        plaintext = AESGCM(shared).decrypt(blob[32:44], blob[44:], None)
        self.assertEqual(json.loads(plaintext), {'env': [{'key': 'ALPHACOMPUTE_DATABASE_URL', 'value': 'postgres://SYNTHETIC-ONLY'}]})

    def test_create_and_update_require_fresh_app_bound_pinned_signatures(self):
        for action in ('create', 'update'):
            for case in ('valid', 'missing-pin', 'wrong-pin', 'unsigned', 'substituted', 'wrong-app', 'stale', 'future'):
                with self.subTest(action=action, case=case): self.exercise(action, case)

    def test_compose_hash_mismatch_stops_the_helper(self):
        with self.assertRaises(SystemExit): phala.check('00' * 32, b'{}')

if __name__ == '__main__': unittest.main(verbosity=2)
