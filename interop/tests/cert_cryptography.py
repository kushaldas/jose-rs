#!/usr/bin/env python3
"""X.509 subject-public-key extraction interop (I4) — against `cryptography`.

    interop/.venv/bin/python interop/tests/cert_cryptography.py

`cryptography` builds the certificates (RSA, EC P-256/P-384/P-521, Ed25519, plus a Brainpool one
on a curve this crate does not support and an indefinite-length BER one), and also serves as the
independent reader of what we produce.

Two things are compared rather than one:

* the **members** of the JWK our harness prints, against the values `cryptography` holds for the
  same key; and
* an **RFC 7638 thumbprint computed here in Python** — the six-member canonical JSON, hashed —
  against `cryptography`'s own DER-encoded public key re-read as a JWK. That second computation
  is deliberately not this crate's code, so a bug in our thumbprint cannot hide a bug in our DER
  walk, or the other way round.
"""

import base64
import datetime
import json
import pathlib
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
HARNESS = ROOT / "interop" / "rust-harness" / "target" / "release" / "jose-interop"

failures = []
checks = 0


def check(ok, detail):
    global checks
    checks += 1
    print(f"  {'ok  ' if ok else 'FAIL'} {detail}")
    if not ok:
        failures.append(detail)


def run(args, stdin=b""):
    return subprocess.run([str(HARNESS), *args], input=stdin, capture_output=True)


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def thumbprint(jwk):
    """RFC 7638 SHA-256 thumbprint, implemented here so it is independent of the crate."""
    import hashlib

    if jwk["kty"] == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif jwk["kty"] == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif jwk["kty"] == "OKP":
        members = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    else:
        raise AssertionError(f"unexpected kty {jwk['kty']}")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode()
    return b64url(hashlib.sha256(canonical).digest())


def jwk_from_cryptography_key(key):
    """The JWK `cryptography` describes this key with, computed from raw key material."""
    if hasattr(key, "private_bytes"):  # a private key object: compare the public half
        key = key.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        numbers = key.public_numbers()
        width = (key.curve.key_size + 7) // 8
        return {
            "kty": "EC",
            "crv": {256: "P-256", 384: "P-384", 521: "P-521"}[key.curve.key_size],
            "x": b64url(numbers.x.to_bytes(width, "big")),
            "y": b64url(numbers.y.to_bytes(width, "big")),
        }
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64url(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        }
    numbers = key.public_numbers()
    width = (numbers.n.bit_length() + 7) // 8
    return {
        "kty": "RSA",
        "n": b64url(numbers.n.to_bytes(width, "big")),
        "e": b64url(numbers.e.to_bytes(3, "big")),
    }


def self_signed(key, name):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3))
        # Ed25519 signs with no separate digest.
        .sign(key, None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )


def main():
    if not HARNESS.exists():
        sys.exit(f"harness missing: {HARNESS} (cargo build --release in interop/rust-harness)")

    print("cryptography-built certificates -> jose-rs")
    keys = {
        "RSA 2048": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "EC P-256": ec.generate_private_key(ec.SECP256R1()),
        "EC P-384": ec.generate_private_key(ec.SECP384R1()),
        "EC P-521": ec.generate_private_key(ec.SECP521R1()),
        "Ed25519": ed25519.Ed25519PrivateKey.generate(),
    }
    for name, key in keys.items():
        pem = self_signed(key, f"jose-rs interop {name}")
        proc = run(["import-cert"], stdin=pem)
        if proc.returncode != 0:
            check(False, f"{name}: extraction failed: {proc.stderr.decode().strip()}")
            continue
        got = json.loads(proc.stdout)
        want = jwk_from_cryptography_key(key)
        for member, value in want.items():
            check(got.get(member) == value, f"{name}: {member} matches")
        check(thumbprint(got) == thumbprint(want), f"{name}: RFC 7638 thumbprint matches (Python-side)")
        check("d" not in got, f"{name}: no private member in the extracted key")
        check("kid" not in got and "use" not in got and "alg" not in got,
              f"{name}: no invented metadata")

    print("\nour own certificates, read back through cryptography's key object")
    for name, key in keys.items():
        pem = self_signed(key, f"jose-rs interop {name}")
        got = json.loads(run(["import-cert"], stdin=pem).stdout)
        # `cryptography`'s own view of the certificate's public key, re-expressed as a JWK.
        peer = jwk_from_cryptography_key(x509.load_pem_x509_certificate(pem).public_key())
        check(thumbprint(got) == thumbprint(peer), f"{name}: extraction agrees with cryptography")

    print("\nrefusals, with the peers' behaviour recorded rather than assumed")
    brainpool_pem = None
    built = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec",
         "-pkeyopt", "ec_paramgen_curve:brainpoolP256r1", "-keyout", "/dev/null",
         "-nodes", "-sha256", "-days", "3", "-subj", "/CN=brainpool", "-out", "/dev/stdout"],
        capture_output=True,
    )
    if built.returncode == 0:
        brainpool_pem = built.stdout
        check(
            x509.load_pem_x509_certificate(brainpool_pem) is not None,
            "cryptography loads the Brainpool certificate",
        )
        proc = run(["import-cert"], stdin=brainpool_pem)
        check(proc.returncode != 0, "we refuse it (unsupported curve)")
        check(b"curve" in proc.stderr or b"OID" in proc.stderr,
              "and we name the curve/OID as the reason")
    else:
        check(False, f"could not build a Brainpool certificate: {built.stderr.decode()[:120]}")

    # An indefinite-length (BER) certificate: OpenSSL reads it, cryptography refuses it.
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = self_signed(rsa_key, "ber case")
    der = x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)
    body = der[2:] if der[1] < 0x80 else der[2 + (der[1] & 0x7F):]
    wrapped = base64.b64encode(b"\x30\x80" + body + b"\x00\x00").decode()
    # Wrapped at 64 characters: RFC 7468's line cap applies to the armor even when the
    # payload inside it is what we are testing.
    indefinite = (
        "-----BEGIN CERTIFICATE-----\n"
        + "\n".join(wrapped[i:i + 64] for i in range(0, len(wrapped), 64))
        + "\n-----END CERTIFICATE-----\n"
    ).encode()
    opensssl = subprocess.run(["openssl", "x509", "-noout"], input=indefinite, capture_output=True)
    peer_reads = opensssl.returncode == 0
    print(f"  note OpenSSL {'accepts' if peer_reads else 'refuses'} the indefinite-length file;"
          f" cryptography refuses it")
    proc = run(["import-cert"], stdin=indefinite)
    check(proc.returncode != 0 and b"indefinite length" in proc.stderr,
          "we refuse it naming the length form (DER-only, RFC 5280 A.1)")

    print(f"\n{checks} checks, {len(failures)} failures")
    if failures:
        for failure in failures:
            print(f"  - {failure}")
        sys.exit(1)


if __name__ == "__main__":
    main()
