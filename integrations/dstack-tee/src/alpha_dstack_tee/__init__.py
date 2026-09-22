"""Use the dependency SDK's crypto; Alpha owns the mandatory verification policy."""

import hmac
import re
from collections.abc import Mapping

from dstack_sdk import EnvVar, encrypt_env_vars_sync, verify_env_encrypt_public_key


def _hex(value: str, size: int, label: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", value):
        raise ValueError(f"invalid {label}")
    raw = bytes.fromhex(value.removeprefix("0x")) if len(value.removeprefix("0x")) % 2 == 0 else b""
    if len(raw) != size:
        raise ValueError(f"invalid {label} length")
    return raw


class AlphaDstackTEEPlugin:
    """An external Alpha adapter, not an in-process dstack guest-agent plugin.

    Pin material is provisioned independently of the response being checked.
    The Phala provider App ID is a 20-byte ID, NOT Alpha's UUID App ID.
    """

    def __init__(self, trusted_signer: str, max_age_seconds: int = 300):
        self._signer = _hex(trusted_signer, 33, "trusted KMS signer")
        if self._signer[0] not in (2, 3):
            raise ValueError("trusted signer must be a compressed secp256k1 public key")
        if type(max_age_seconds) is not int or not 1 <= max_age_seconds <= 300:
            raise ValueError("signature age must be between 1 and 300 seconds")
        self._max_age = max_age_seconds

    def encrypt_environment(
        self,
        values: Mapping[str, str],
        *,
        expected_app_id: str,
        offered_public_key: str,
        signed_key: Mapping,
    ) -> str:
        app_id = _hex(expected_app_id, 20, "provider App ID")
        offered = _hex(offered_public_key, 32, "offered environment key")
        if not isinstance(signed_key, Mapping):
            raise ValueError("signed environment key is required")
        key = _hex(signed_key.get("public_key"), 32, "signed environment key")
        signature = _hex(signed_key.get("signature_v1"), 65, "timestamped signature")
        timestamp = signed_key.get("timestamp")
        if type(timestamp) is not int or not 0 <= timestamp < 2**64:
            raise ValueError("invalid signature timestamp")
        signer = verify_env_encrypt_public_key(
            key, signature, app_id.hex(), timestamp, max_age_seconds=self._max_age
        )
        if signer is None or not hmac.compare_digest(
            _hex(signer, 33, "recovered signer"), self._signer
        ):
            raise ValueError("environment key was not freshly signed by the pinned KMS")
        if not hmac.compare_digest(key, offered):
            raise ValueError("provisioning and signed environment keys differ")
        # Inspect values only after authenticating the destination. Never print
        # values, responses, ciphertext, or provider errors from this library.
        if not isinstance(values, Mapping) or any(
            not isinstance(k, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k)
            or not isinstance(v, str) for k, v in values.items()
        ):
            raise ValueError("environment must map valid names to strings")
        return encrypt_env_vars_sync([EnvVar(k, v) for k, v in values.items()], key.hex())
