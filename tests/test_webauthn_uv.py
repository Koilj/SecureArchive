import json
import unittest

import cbor2

from webauthn_utils import b64url_encode, verify_authentication_response, verify_registration_response


def _client_data(challenge: str, origin: str, typ: str) -> str:
    return b64url_encode(json.dumps({
        "type": typ,
        "challenge": challenge,
        "origin": origin,
    }).encode("utf-8"))


class WebAuthnUserVerificationTests(unittest.TestCase):
    def test_registration_requires_uv_flag(self):
        challenge = b64url_encode(b"challenge")
        rp_id = "localhost"
        origin = "http://localhost:8000"
        rp_hash = __import__("hashlib").sha256(rp_id.encode("utf-8")).digest()
        auth_data = (
            rp_hash
            + bytes([0x01 | 0x40])
            + (1).to_bytes(4, "big")
            + b"\x00" * 16
            + (1).to_bytes(2, "big")
            + b"x"
            + cbor2.dumps({})
        )
        credential = {
            "response": {
                "clientDataJSON": _client_data(challenge, origin, "webauthn.create"),
                "attestationObject": b64url_encode(cbor2.dumps({"fmt": "none", "authData": auth_data, "attStmt": {}})),
            }
        }
        with self.assertRaisesRegex(ValueError, "user verification"):
            verify_registration_response(
                credential=credential,
                expected_challenge_b64=challenge,
                expected_origin=origin,
                expected_rp_id=rp_id,
            )

    def test_authentication_requires_uv_flag(self):
        challenge = b64url_encode(b"challenge")
        rp_id = "localhost"
        origin = "http://localhost:8000"
        rp_hash = __import__("hashlib").sha256(rp_id.encode("utf-8")).digest()
        auth_data = rp_hash + bytes([0x01]) + (1).to_bytes(4, "big")
        credential = {
            "id": "cred",
            "response": {
                "clientDataJSON": _client_data(challenge, origin, "webauthn.get"),
                "authenticatorData": b64url_encode(auth_data),
                "signature": b64url_encode(b"signature"),
            },
        }
        with self.assertRaisesRegex(ValueError, "user verification"):
            verify_authentication_response(
                credential=credential,
                expected_challenge_b64=challenge,
                expected_origin=origin,
                expected_rp_id=rp_id,
                stored_public_key_pem="-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n",
                stored_sign_count=0,
            )


if __name__ == "__main__":
    unittest.main()
