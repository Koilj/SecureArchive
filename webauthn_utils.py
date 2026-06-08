import base64
import hashlib
import json
import struct
from dataclasses import dataclass

try:
    import cbor2
except Exception:  # pragma: no cover - optional dependency fallback
    cbor2 = None

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    raw = str(data or "").encode("ascii")
    raw += b"=" * ((4 - (len(raw) % 4)) % 4)
    return base64.urlsafe_b64decode(raw)


class CBORError(ValueError):
    pass


class _CBORReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise CBORError("truncated cbor")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def read_uint(self, addl: int) -> int:
        if addl < 24:
            return addl
        if addl == 24:
            return self.read(1)[0]
        if addl == 25:
            return struct.unpack(">H", self.read(2))[0]
        if addl == 26:
            return struct.unpack(">I", self.read(4))[0]
        if addl == 27:
            return struct.unpack(">Q", self.read(8))[0]
        raise CBORError("unsupported integer encoding")

    def item(self):
        ib = self.read(1)[0]
        major = ib >> 5
        addl = ib & 0x1F
        if major == 0:
            return self.read_uint(addl)
        if major == 1:
            return -1 - self.read_uint(addl)
        if major == 2:
            ln = self.read_uint(addl)
            return self.read(ln)
        if major == 3:
            ln = self.read_uint(addl)
            return self.read(ln).decode("utf-8")
        if major == 4:
            ln = self.read_uint(addl)
            return [self.item() for _ in range(ln)]
        if major == 5:
            ln = self.read_uint(addl)
            out = {}
            for _ in range(ln):
                out[self.item()] = self.item()
            return out
        if major == 7:
            if addl == 20:
                return False
            if addl == 21:
                return True
            if addl == 22:
                return None
        raise CBORError(f"unsupported cbor major={major} addl={addl}")


def cbor_decode(data: bytes):
    if cbor2 is not None:
        return cbor2.loads(data)
    reader = _CBORReader(data)
    value = reader.item()
    if reader.pos != len(data):
        raise CBORError("extra trailing cbor bytes")
    return value


@dataclass
class ParsedAuthenticatorData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    credential_id: bytes = b""
    credential_public_key_cose: bytes = b""
    aaguid: bytes = b""


def parse_authenticator_data(auth_data: bytes) -> ParsedAuthenticatorData:
    if len(auth_data) < 37:
        raise ValueError("authenticatorData too short")
    rp_id_hash = auth_data[:32]
    flags = auth_data[32]
    sign_count = struct.unpack(">I", auth_data[33:37])[0]
    pos = 37

    credential_id = b""
    credential_public_key_cose = b""
    aaguid = b""

    if flags & 0x40:
        if len(auth_data) < pos + 18:
            raise ValueError("authenticatorData missing attestedCredentialData")
        aaguid = auth_data[pos : pos + 16]
        pos += 16
        cred_len = struct.unpack(">H", auth_data[pos : pos + 2])[0]
        pos += 2
        if len(auth_data) < pos + cred_len:
            raise ValueError("credential id truncated")
        credential_id = auth_data[pos : pos + cred_len]
        pos += cred_len
        credential_public_key_cose = auth_data[pos:]
        if not credential_public_key_cose:
            raise ValueError("credential public key missing")

    return ParsedAuthenticatorData(
        rp_id_hash=rp_id_hash,
        flags=flags,
        sign_count=sign_count,
        credential_id=credential_id,
        credential_public_key_cose=credential_public_key_cose,
        aaguid=aaguid,
    )


def cose_key_to_pem(cose_key: bytes) -> str:
    key = cbor_decode(cose_key)
    if not isinstance(key, dict):
        raise ValueError("credentialPublicKey must be a CBOR map")
    kty = key.get(1)
    alg = key.get(3)

    if kty == 2 and alg == -7:
        curve = key.get(-1)
        x = key.get(-2)
        y = key.get(-3)
        if curve != 1 or not isinstance(x, bytes) or not isinstance(y, bytes):
            raise ValueError("unsupported EC2 COSE key")
        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x, "big"),
            y=int.from_bytes(y, "big"),
            curve=ec.SECP256R1(),
        )
        public_key = public_numbers.public_key()
    elif kty == 3 and alg == -257:
        n = key.get(-1)
        e = key.get(-2)
        if not isinstance(n, bytes) or not isinstance(e, bytes):
            raise ValueError("unsupported RSA COSE key")
        public_numbers = rsa.RSAPublicNumbers(
            e=int.from_bytes(e, "big"),
            n=int.from_bytes(n, "big"),
        )
        public_key = public_numbers.public_key()
    else:
        raise ValueError(f"unsupported COSE key kty={kty} alg={alg}")

    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _verify_challenge(client_data_b64: str, expected_challenge_b64: str, expected_origin: str, expected_type: str) -> bytes:
    client_data_json = b64url_decode(client_data_b64)
    client_data = json.loads(client_data_json.decode("utf-8"))
    if client_data.get("type") != expected_type:
        raise ValueError("unexpected clientData type")
    if client_data.get("challenge") != expected_challenge_b64:
        raise ValueError("challenge mismatch")
    if client_data.get("origin") != expected_origin:
        raise ValueError("origin mismatch")
    return client_data_json


def verify_registration_response(
    *,
    credential: dict,
    expected_challenge_b64: str,
    expected_origin: str,
    expected_rp_id: str,
):
    response = credential.get("response") or {}
    client_data_json = _verify_challenge(
        response.get("clientDataJSON", ""),
        expected_challenge_b64,
        expected_origin,
        "webauthn.create",
    )
    attestation_object = cbor_decode(b64url_decode(response.get("attestationObject", "")))
    if not isinstance(attestation_object, dict):
        raise ValueError("attestationObject must be a CBOR map")

    fmt = str(attestation_object.get("fmt") or "")
    if fmt != "none":
        raise ValueError("unsupported attestation format")

    auth_data = attestation_object.get("authData")
    if not isinstance(auth_data, bytes):
        raise ValueError("authData missing")
    parsed = parse_authenticator_data(auth_data)

    if parsed.rp_id_hash != hashlib.sha256(expected_rp_id.encode("utf-8")).digest():
        raise ValueError("rpIdHash mismatch")
    if not (parsed.flags & 0x01):
        raise ValueError("user presence flag not set")
    if not (parsed.flags & 0x04):
        raise ValueError("user verification flag not set")
    if not (parsed.flags & 0x40):
        raise ValueError("attested credential data missing")

    public_key_pem = cose_key_to_pem(parsed.credential_public_key_cose)
    transports = []
    for item in credential.get("transports") or []:
        text = str(item or "").strip()
        if text:
            transports.append(text)

    return {
        "credential_id": b64url_encode(parsed.credential_id),
        "public_key_pem": public_key_pem,
        "sign_count": parsed.sign_count,
        "aaguid": parsed.aaguid.hex(),
        "attestation_format": fmt,
        "client_data_json": client_data_json,
        "authenticator_data": auth_data,
        "transports": transports,
    }


def verify_authentication_response(
    *,
    credential: dict,
    expected_challenge_b64: str,
    expected_origin: str,
    expected_rp_id: str,
    stored_public_key_pem: str,
    stored_sign_count: int,
):
    response = credential.get("response") or {}
    client_data_json = _verify_challenge(
        response.get("clientDataJSON", ""),
        expected_challenge_b64,
        expected_origin,
        "webauthn.get",
    )
    auth_data = b64url_decode(response.get("authenticatorData", ""))
    parsed = parse_authenticator_data(auth_data)
    if parsed.rp_id_hash != hashlib.sha256(expected_rp_id.encode("utf-8")).digest():
        raise ValueError("rpIdHash mismatch")
    if not (parsed.flags & 0x01):
        raise ValueError("user presence flag not set")
    if not (parsed.flags & 0x04):
        raise ValueError("user verification flag not set")

    signed_data = auth_data + hashlib.sha256(client_data_json).digest()
    signature = b64url_decode(response.get("signature", ""))
    public_key = serialization.load_pem_public_key(stored_public_key_pem.encode("utf-8"))

    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, signed_data, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise ValueError("unsupported WebAuthn public key type")
    except InvalidSignature as exc:
        raise ValueError("assertion signature invalid") from exc

    new_sign_count = parsed.sign_count
    prev = int(stored_sign_count or 0)
    if prev and new_sign_count and new_sign_count <= prev:
        raise ValueError("signCount did not increase")

    return {
        "credential_id": str(credential.get("id") or ""),
        "sign_count": new_sign_count,
        "user_handle": str(response.get("userHandle") or ""),
        "authenticator_data": auth_data,
        "client_data_json": client_data_json,
    }
