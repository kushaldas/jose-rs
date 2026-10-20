#!/usr/bin/env python3
"""Cross-check this crate's ECDH + JOSE Concat KDF against independent ones.

Key agreement is where an implementation can be silently wrong: a mis-encoded
`OtherInfo`, a `0x04` prefix missing, a coordinate left-padded on the wrong
side — all produce a shared secret that *looks* fine and decrypts nothing. So
this script compares the Rust harness against two implementations it does not
share a line of code with:

* **`cryptography` (OpenSSL)** for the scalar multiplication, and
* a Python transcription of **RFC 7518 §4.6.2's** Concat KDF construction,
  written from the spec text rather than from the Rust code.

and against the RFC's own published numbers (Appendix C: both private keys, the
shared secret, every KDF parameter, and the derived key).

Run after building the harness:
    cargo build --release --locked --manifest-path interop/rust-harness/Cargo.toml
"""

import hashlib
import json
import os
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric import ec

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(HERE, "..", "rust-harness", "target", "release", "jose-interop")

CURVES = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}

FAILURES = []
PASSES = []


def check(name, actual, expected):
    if actual == expected:
        PASSES.append(name)
    else:
        FAILURES.append(f"{name}: got {actual!r}, want {expected!r}")


def harness(command, payload):
    proc = subprocess.run(
        [HARNESS, command],
        input=json.dumps(payload).encode(),
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(f"{command} exited {proc.returncode}: {proc.stderr.decode()}")
    return json.loads(proc.stdout)


def public_half(jwk):
    """A JWK with the private component removed — what an `epk` carries."""
    out = dict(jwk)
    out.pop("d", None)
    return out


def b64u(raw):
    import base64

    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def python_ecdh(private_key, peer_public_key):
    """Z, computed by OpenSSL."""
    return private_key.exchange(ec.ECDH(), peer_public_key)


def python_concat_kdf(z, key_len, algorithm_id, party_u, party_v):
    """Concat KDF, RFC 7518 §4.6.2, transcribed from the spec.

    OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo, where
    each of the first three is `Datalen || Data` with a big-endian 32-bit
    Datalen and SuppPubInfo is the key length in bits as 32 bits big-endian.
    The Digest Method is SHA-256.
    """

    def prefixed(data):
        return len(data).to_bytes(4, "big") + data

    other = (
        prefixed(algorithm_id.encode())
        + prefixed(party_u)
        + prefixed(party_v)
        + (key_len * 8).to_bytes(4, "big")
    )
    digest = hashlib.sha256
    key, counter = b"", 1
    while len(key) < key_len:
        key += digest(counter.to_bytes(4, "big") + z + other).digest()
        counter += 1
    return key[:key_len]


def jwk_of(private, include_private=True):
    """A JWK for a `cryptography` private key — with or without `d`."""
    numbers = private.public_key().public_numbers()
    curve_name = private.curve.name
    crv = {
        "secp256r1": "P-256",
        "secp384r1": "P-384",
        "secp521r1": "P-521",
    }[curve_name]
    size = private.curve.key_size // 8 + (1 if private.curve.key_size % 8 else 0)
    out = {
        "kty": "EC",
        "crv": crv,
        "x": b64u(numbers.x.to_bytes(size, "big")),
        "y": b64u(numbers.y.to_bytes(size, "big")),
    }
    if include_private:
        out["d"] = b64u(private.private_numbers().private_value.to_bytes(size, "big"))
    return out


def public_jwk_of(public):
    numbers = public.public_numbers()
    crv = {
        "secp256r1": "P-256",
        "secp384r1": "P-384",
        "secp521r1": "P-521",
    }[public.curve.name]
    size = public.curve.key_size // 8 + (1 if public.curve.key_size % 8 else 0)
    return {
        "kty": "EC",
        "crv": crv,
        "x": b64u(numbers.x.to_bytes(size, "big")),
        "y": b64u(numbers.y.to_bytes(size, "big")),
    }


# ---------------------------------------------------------------- RFC 7518 §C
# Alice's ephemeral key and Bob's static key, verbatim from the RFC, with the
# private parts — the RFC prints Z, the OtherInfo bytes and the derived key, so
# every step is checkable rather than self-consistent.
ALICE = {
    "kty": "EC",
    "crv": "P-256",
    "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
    "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
    "d": "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo",
}
BOB = {
    "kty": "EC",
    "crv": "P-256",
    "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
    "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
    "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
}
RFC_Z = bytes(
    [
        158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156,
        251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
    ]
)
RFC_DERIVED = "VqqN6vgjbSBcIijNcacQGg"
APU, APV = "QWxpY2U", "Qm9i"  # base64url("Alice"), base64url("Bob")


def rfc_appendix_c():
    import base64

    decode = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    # 1. Both directions of agreement, against the RFC's printed Z.
    out = harness("agree", {"own_jwk": ALICE, "peer_jwk": public_half(BOB)})
    check("rfc-C: Alice's Z matches the RFC", decode(out["z_b64u"]), RFC_Z)
    out = harness("agree", {"own_jwk": BOB, "peer_jwk": public_half(ALICE)})
    check("rfc-C: Bob's Z matches the RFC", decode(out["z_b64u"]), RFC_Z)

    # 2. The derived key, against the RFC's printed value...
    derived = harness(
        "derive-key",
        {
            "own_jwk": ALICE,
            "peer_jwk": public_half(BOB),
            "alg_id": "A128GCM",
            "apu": APU,
            "apv": APV,
            "key_len": 16,
        },
    )
    check("rfc-C: derived key matches the RFC", derived["derived_b64u"], RFC_DERIVED)

    # 3. ...and against Python's own independent KDF over Python's own ECDH.
    alice_priv = ec.derive_private_key(int.from_bytes(decode(ALICE["d"]), "big"), ec.SECP256R1())
    bob_pub = ec.EllipticCurvePublicNumbers(
        int.from_bytes(decode(BOB["x"]), "big"),
        int.from_bytes(decode(BOB["y"]), "big"),
        ec.SECP256R1(),
    ).public_key()
    z_py = python_ecdh(alice_priv, bob_pub)
    check("rfc-C: OpenSSL's Z matches the RFC", z_py, RFC_Z)
    key_py = python_concat_kdf(z_py, 16, "A128GCM", decode(APU), decode(APV))
    check(
        "rfc-C: Python's KDF agrees with the harness",
        b64u(key_py),
        derived["derived_b64u"],
    )


def curve_roundtrip(crv):
    """Random key pairs: harness Z == OpenSSL Z, both directions, plus KDF."""
    priv_a = ec.generate_private_key(CURVES[crv])
    priv_b = ec.generate_private_key(CURVES[crv])

    z_harness_ab = harness(
        "agree", {"own_jwk": jwk_of(priv_a), "peer_jwk": public_jwk_of(priv_b.public_key())}
    )["z_b64u"]
    z_harness_ba = harness(
        "agree", {"own_jwk": jwk_of(priv_b), "peer_jwk": public_jwk_of(priv_a.public_key())}
    )["z_b64u"]
    z_py = python_ecdh(priv_a, priv_b.public_key())

    import base64

    decode = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    check(f"{crv}: harness agreement is symmetric", z_harness_ab, z_harness_ba)
    check(f"{crv}: harness Z matches OpenSSL", decode(z_harness_ab), z_py)

    # The KDF over that Z, cross-checked with the Python transcription. The
    # apu/apv here are deliberately not multiples of 4 bytes: an
    # implementation that forgot the length prefix would still produce the same
    # bytes for ASCII names of matching length, so mixed lengths are the case
    # that catches it.
    apu, apv = b64u(b"sender-side"), b64u(b"r")
    derived = harness(
        "derive-key",
        {
            "own_jwk": jwk_of(priv_a),
            "peer_jwk": public_jwk_of(priv_b.public_key()),
            "alg_id": "ECDH-ES+A128KW",
            "apu": apu,
            "apv": apv,
            "key_len": 16,
        },
    )
    key_py = python_concat_kdf(z_py, 16, "ECDH-ES+A128KW", decode(apu), decode(apv))
    check(f"{crv}: KDF matches the Python transcription", decode(derived["derived_b64u"]), key_py)


def refusals():
    """The boundary must refuse, and refuse loudly, not derive something odd."""

    def expect_error(command, payload, needle, name):
        proc = subprocess.run(
            [HARNESS, command],
            input=json.dumps(payload).encode(),
            capture_output=True,
            check=False,
        )
        if proc.returncode == 0:
            FAILURES.append(f"{name}: harness accepted a key pair it must refuse")
        elif needle not in proc.stderr.decode():
            FAILURES.append(
                f"{name}: stderr {proc.stderr.decode()!r} does not mention {needle!r}"
            )
        else:
            PASSES.append(name)

    # Private material in the peer position.
    expect_error(
        "agree",
        {"own_jwk": ALICE, "peer_jwk": BOB},
        "private component",
        "refusal: peer key with d",
    )
    # A signing-pinned key as one's own half.
    expect_error(
        "agree",
        {"own_jwk": {**BOB, "key_ops": ["sign"]}, "peer_jwk": public_jwk_of(
            ec.derive_private_key(2, ec.SECP256R1()).public_key()
        )},
        "key_ops",
        "refusal: own key pinned to sign",
    )
    # Curve mismatch.
    p384 = ec.generate_private_key(ec.SECP384R1())
    expect_error(
        "agree",
        {"own_jwk": ALICE, "peer_jwk": public_jwk_of(p384.public_key())},
        "curve mismatch",
        "refusal: P-256 scalar against a P-384 point",
    )
    # An off-curve peer point: right shape, wrong curve membership.
    bogus = dict(public_jwk_of(ec.generate_private_key(ec.SECP256R1()).public_key()))
    bogus["y"] = b64u(bytes(32))
    expect_error(
        "agree",
        {"own_jwk": ALICE, "peer_jwk": bogus},
        "key error",
        "refusal: off-curve peer point",
    )
    # apu == apv.
    proc_failed = False
    out = subprocess.run(
        [HARNESS, "derive-key"],
        input=json.dumps(
            {
                "own_jwk": ALICE,
                "peer_jwk": public_jwk_of(
                    ec.derive_private_key(2, ec.SECP256R1()).public_key()
                ),
                "alg_id": "A128GCM",
                "apu": APU,
                "apv": APU,
                "key_len": 16,
            }
        ).encode(),
        capture_output=True,
        check=False,
    )
    if out.returncode == 0:
        FAILURES.append("refusal: apu == apv was accepted")
    elif "distinct" not in out.stderr.decode():
        FAILURES.append(f"refusal: apu == apv failed for the wrong reason: {out.stderr.decode()!r}")
    else:
        PASSES.append("refusal: apu == apv")


def main():
    if not os.path.exists(HARNESS):
        sys.exit(f"harness not found at {HARNESS}; build it first")
    rfc_appendix_c()
    for crv in ("P-256", "P-384", "P-521"):
        curve_roundtrip(crv)
    refusals()

    for line in PASSES:
        print(f"  ok   {line}")
    if FAILURES:
        for line in FAILURES:
            print(f"  FAIL {line}")
        print(f"\nECDH/Concat-KDF interop: {len(PASSES)} passed, {len(FAILURES)} failed")
        sys.exit(1)
    print(f"\nECDH/Concat-KDF interop: {len(PASSES)} passed, 0 failed")


if __name__ == "__main__":
    main()
