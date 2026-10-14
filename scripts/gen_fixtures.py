# Generate WebAuthn responses with an independent Python implementation and record what
# the py_webauthn relying-party library concludes from them.
#
#   uv run --no-project --with webauthn==2.7.0 --with fido2==2.2.1 \
#     --with cryptography==50.0.2 python scripts/gen_fixtures.py test/vectors/python
#
# Each fixture is a registration followed by assertions, made by a software
# authenticator written here with `cryptography` (keys, signatures) and `fido2`
# (CBOR). Every response is first verified by py_webauthn; its outputs are stored
# under "expected" so the OCaml tests can compare field by field.
import base64, hashlib, json, os, struct, sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from fido2 import cbor
import webauthn
from webauthn.helpers.structs import AuthenticatorTransport

RP_ID = "example.org"
ORIGIN = "https://example.org"


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sha256(b):
    return hashlib.sha256(b).digest()


class Authenticator:
    def __init__(self, seed, alg, aaguid, be, counting):
        self.alg = alg
        self.aaguid = aaguid
        self.be = be
        self.counting = counting
        self.counter = 0
        self.cred_id = sha256(b"credential " + seed)[:20]
        if alg == -7:
            d = int.from_bytes(sha256(b"key " + seed), "big")
            self.key = ec.derive_private_key(d, ec.SECP256R1())
            n = self.key.public_key().public_numbers()
            self.cose = {1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}
        else:
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            n = self.key.public_key().public_numbers()
            self.cose = {1: 3, 3: -257, -1: n.n.to_bytes(256, "big"), -2: n.e.to_bytes(3, "big")}

    def sign(self, msg):
        if self.alg == -7:
            return self.key.sign(msg, ec.ECDSA(hashes.SHA256()))
        return self.key.sign(msg, padding.PKCS1v15(), hashes.SHA256())

    def flags(self, at, uv, bs):
        return 0x01 | (0x04 if uv else 0) | (0x08 if self.be else 0) | (0x10 if bs else 0) | (0x40 if at else 0)

    def client_data(self, typ, challenge):
        return json.dumps(
            {"type": typ, "challenge": b64(challenge), "origin": ORIGIN, "crossOrigin": False},
            separators=(",", ":"),
        ).encode()

    def register(self, challenge, fmt, uv=True, bs=False):
        cdj = self.client_data("webauthn.create", challenge)
        auth_data = (
            sha256(RP_ID.encode())
            + bytes([self.flags(True, uv, bs)])
            + struct.pack(">I", self.counter)
            + self.aaguid
            + struct.pack(">H", len(self.cred_id))
            + self.cred_id
            + cbor.encode(self.cose)
        )
        if fmt == "none":
            stmt = {}
        else:
            stmt = {"alg": self.alg, "sig": self.sign(auth_data + sha256(cdj))}
        att = cbor.encode({"fmt": fmt, "attStmt": stmt, "authData": auth_data})
        return {
            "id": b64(self.cred_id),
            "rawId": b64(self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(cdj),
                "attestationObject": b64(att),
                "transports": ["usb", "nfc"] if not self.be else ["internal", "hybrid"],
            },
            "authenticatorAttachment": "platform" if self.be else "cross-platform",
            "clientExtensionResults": {"credProps": {"rk": True}},
        }

    def authenticate(self, challenge, user_handle, uv=True, bs=False):
        if self.counting:
            self.counter += 1
        cdj = self.client_data("webauthn.get", challenge)
        auth_data = sha256(RP_ID.encode()) + bytes([self.flags(False, uv, bs)]) + struct.pack(">I", self.counter)
        sig = self.sign(auth_data + sha256(cdj))
        return {
            "id": b64(self.cred_id),
            "rawId": b64(self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(cdj),
                "authenticatorData": b64(auth_data),
                "signature": b64(sig),
                "userHandle": b64(user_handle),
            },
            "clientExtensionResults": {},
        }


def fixture(name, alg, fmt, be, counting, assertions):
    seed = name.encode()
    aaguid = sha256(b"aaguid " + seed)[:16] if fmt != "none" else bytes(16)
    a = Authenticator(seed, alg, aaguid, be, counting)
    user_handle = sha256(b"user " + seed)[:16]
    reg_challenge = sha256(b"registration challenge " + seed)
    reg = a.register(reg_challenge, fmt, bs=be)
    v = webauthn.verify_registration_response(
        credential=reg,
        expected_challenge=reg_challenge,
        expected_rp_id=RP_ID,
        expected_origin=ORIGIN,
        require_user_verification=True,
    )
    out = {
        "name": name,
        "generator": "scripts/gen_fixtures.py (py_webauthn 2.7.0, fido2 2.2.1, cryptography 50.0.2)",
        "rp_id": RP_ID,
        "origin": ORIGIN,
        "user_handle": b64(user_handle),
        "registration": {
            "challenge": b64(reg_challenge),
            "response": reg,
            "expected": {
                "credential_id": b64(v.credential_id),
                "credential_public_key": b64(v.credential_public_key),
                "sign_count": v.sign_count,
                "aaguid": v.aaguid,
                "fmt": v.fmt.value if hasattr(v.fmt, "value") else str(v.fmt),
                "user_verified": v.user_verified,
                "backup_eligible": v.credential_device_type.value == "multi_device",
                "backed_up": v.credential_backed_up,
            },
        },
        "authentications": [],
    }
    sign_count = v.sign_count
    for i, (uv, bs) in enumerate(assertions):
        ch = sha256(b"authentication challenge %d " % i + seed)
        resp = a.authenticate(ch, user_handle, uv=uv, bs=bs and be)
        va = webauthn.verify_authentication_response(
            credential=resp,
            expected_challenge=ch,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=v.credential_public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=False,
        )
        sign_count = va.new_sign_count
        out["authentications"].append(
            {
                "challenge": b64(ch),
                "response": resp,
                "expected": {
                    "new_sign_count": va.new_sign_count,
                    "user_verified": va.user_verified,
                    "backed_up": va.credential_backed_up,
                },
            }
        )
    return out


def main():
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    cases = [
        ("es256-none-security-key", -7, "none", False, True, [(True, False), (False, False), (True, False)]),
        ("es256-packed-self", -7, "packed", False, True, [(True, False)]),
        ("es256-none-passkey", -7, "none", True, False, [(True, True), (True, False)]),
        ("rs256-none", -257, "none", False, True, [(True, False), (True, False)]),
        ("rs256-packed-self", -257, "packed", False, True, [(True, False)]),
    ]
    for case in cases:
        f = fixture(*case)
        with open(os.path.join(out_dir, case[0] + ".json"), "w") as fh:
            json.dump(f, fh, indent=1, sort_keys=True)
            fh.write("\n")
        print(case[0], "verified by py_webauthn")


main()
