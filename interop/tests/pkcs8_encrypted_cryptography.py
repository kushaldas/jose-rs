#!/usr/bin/env python3
"""Password-encrypted PKCS#8 interop (I3) — against `cryptography` and OpenSSL.

    interop/.venv/bin/python interop/tests/pkcs8_encrypted_cryptography.py

The peer here is **cryptography**, not jwcrypto: jwcrypto has no password-based key-file API
at all (`jwcrypto.jwk.JWK` imports/exports JWK JSON and PEM of the *unencrypted* kind only),
so for RFC 5958 files the implementation that matters is the one everyone else's tooling is
built on. OpenSSL is used as a third opinion.

The claim under test is not "we parse each other's files" but "**the same key comes out**",
plus the refusals: what we decline, we decline by name, and we decline it for files that other
implementations read happily (so the refusal is our policy, not a broken fixture).
"""

import base64
import pathlib
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
HARNESS = ROOT / "interop" / "rust-harness" / "target" / "release" / "jose-interop"
PASSWORD = "hunter2"

failures = []
checks = 0


def check(ok, detail):
    global checks
    checks += 1
    if ok:
        print(f"  ok   {detail}")
    else:
        print(f"  FAIL {detail}")
        failures.append(detail)


def run(args, stdin=b""):
    return subprocess.run([str(HARNESS), *args], input=stdin, capture_output=True)


def parse_pem(text):
    """DER bytes of the first PEM block, so parameter claims are read from the real file."""
    body = [line for line in text.splitlines() if not line.startswith("-----")]
    return base64.b64decode("".join(body))


def pbes2_parameters(der):
    """(kdf-oid-tail, prf-oid-tail, iteration-count, cipher-oid-tail) from the file itself.

    Parsed with OpenSSL's asn1parse instead of a DER library, because the point is what a
    *third* implementation sees.
    """
    out = subprocess.run(
        ["openssl", "asn1parse", "-inform", "DER"], input=der, capture_output=True
    ).stdout.decode()
    kdf = prf = cipher = None
    iterations = None
    for line in out.splitlines():
        if "OBJECT" not in line and "INTEGER" not in line:
            continue
        value = line.rsplit(":", 1)[-1].strip()
        if value.startswith("PBKDF2") or value.startswith("scrypt") or value.startswith("PBES1"):
            kdf = value
        elif value.startswith("hmacWith"):
            prf = value
        elif "cbc" in value:
            cipher = value
        elif "INTEGER" in line and iterations is None:
            try:
                iterations = int(value, 16)
            except ValueError:
                pass
    return kdf, prf, iterations, cipher


def jwk_of(key):
    """The JWK `cryptography` would describe this key with, for coordinate comparison."""
    if isinstance(key, ed25519.Ed25519PrivateKey):
        raw_public = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        raw_private = key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
        return {"kty": "OKP", "crv": "Ed25519", "x": base64url(raw_public, 32),
                "d": base64url(raw_private, 32)}
    numbers = key.private_numbers()
    public = numbers.public_numbers
    if isinstance(key, ec.EllipticCurvePrivateKey):
        size = key.curve.key_size
        width = (size + 7) // 8
        return {
            "kty": "EC",
            "crv": {256: "P-256", 384: "P-384", 521: "P-521"}[size],
            "x": base64url(public.x, width),
            "y": base64url(public.y, width),
            "d": base64url(numbers.private_value, width),
        }
    return {"kty": "RSA", "n": base64url(public.n, (public.n.bit_length() + 7) // 8),
            "e": base64url(public.e, 3), "d": base64url(numbers.d, (numbers.d.bit_length() + 7) // 8)}


def base64url(value, width):
    if isinstance(value, int):
        value = value.to_bytes(width, "big")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def emit_pem(der, label="ENCRYPTED PRIVATE KEY"):
    wrapped = "\n".join(
        base64.b64encode(der)[i : i + 64].decode() for i in range(0, len(base64.b64encode(der)), 64)
    )
    return f"-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----\n"


def main():
    if not HARNESS.exists():
        sys.exit(f"harness missing: {HARNESS} (cargo build --release in interop/rust-harness)")

    keys = {
        "EC P-256": ec.generate_private_key(ec.SECP256R1()),
        "EC P-384": ec.generate_private_key(ec.SECP384R1()),
        "RSA 2048": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "Ed25519": ed25519.Ed25519PrivateKey.generate(),
    }

    print("cryptography -> jose-rs (their encrypted files)")
    for name, key in keys.items():
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(PASSWORD.encode()),
        )
        # The claim behind PKCS8_MIN_ITERATIONS, re-checked on every run.
        _kdf, prf, iterations, cipher = pbes2_parameters(parse_pem(pem.decode()))
        if name == "EC P-256":
            check(iterations == 2048, f"cryptography default iterations = {iterations}")
            check(prf == "hmacWithSHA256", f"cryptography default PRF = {prf}")
            check(cipher == "aes-256-cbc", f"cryptography default cipher = {cipher}")

        proc = run(["import-pkcs8-encrypted", "--password", PASSWORD], stdin=pem)
        if proc.returncode != 0:
            check(False, f"{name}: import failed: {proc.stderr.decode().strip()}")
            continue
        import json

        got = json.loads(proc.stdout)
        want = jwk_of(key)
        for member in ("kty", "crv", "x", "y", "d", "n", "e"):
            if member in want:
                check(got.get(member) == want[member], f"{name}: {member} matches after decrypt")

        # Wrong password must not produce a key.
        bad = run(["import-pkcs8-encrypted", "--password", "not-it"], stdin=pem)
        check(
            bad.returncode != 0 and b"decryption failed" in bad.stderr,
            f"{name}: wrong password refused with a decryption failure",
        )

    print("\njose-rs -> cryptography (our encrypted files)")
    for name, key in keys.items():
        # Build the JWK from the key, in the JSON shape the library itself reads.
        want = jwk_of(key)
        jwk_json = ('{"kty":"%s"' % want["kty"]) + "".join(
            f',"{m}":"{want[m]}"' for m in ("crv", "x", "y", "d", "n", "e") if m in want
        ) + "}"
        proc = run(
            ["export-pkcs8-encrypted", "--password", PASSWORD, "--iterations", "2048"],
            stdin=jwk_json.encode(),
        )
        if proc.returncode != 0:
            check(False, f"{name}: export failed: {proc.stderr.decode().strip()}")
            continue
        pem = proc.stdout.decode()
        check(
            pem.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"),
            f"{name}: our file carries the RFC 7468 encrypted label",
        )
        check(
            all(len(line) <= 64 for line in pem.splitlines() if not line.startswith("-----")),
            f"{name}: our base64 lines respect RFC 7468's 64-character cap",
        )

        loaded = serialization.load_pem_private_key(
            pem.encode(), password=PASSWORD.encode()
        )
        got = jwk_of(loaded)
        for member in ("kty", "crv", "x", "y", "d", "n", "e"):
            if member in want:
                check(got.get(member) == want[member], f"{name}: cryptography recovers {member}")

        # The same file, read by OpenSSL.
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
            handle.write(pem)
            path = handle.name
        openssl = subprocess.run(
            ["openssl", "pkey", "-inform", "PEM", "-in", path, "-passin", f"pass:{PASSWORD}", "-noout"],
            capture_output=True,
        )
        pathlib.Path(path).unlink()
        check(openssl.returncode == 0, f"{name}: OpenSSL pkey decrypts our file")

        # And our own reader takes it back, so we never write a file we cannot open.
        back = run(["import-pkcs8-encrypted", "--password", PASSWORD], stdin=pem.encode())
        check(back.returncode == 0, f"{name}: our reader accepts our own file")

    print("\nrefusals are our policy, not a broken fixture")
    with tempfile.TemporaryDirectory() as tmp:
        src = keys["EC P-256"].private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        src_path = pathlib.Path(tmp) / "plain.pem"
        src_path.write_bytes(src)
        des3_path = pathlib.Path(tmp) / "des3.pem"
        generated = subprocess.run(
            [
                "openssl", "pkcs8", "-topk8", "-in", str(src_path), "-out", str(des3_path),
                "-v2", "des3", "-passout", f"pass:{PASSWORD}",
            ],
            capture_output=True,
        )
        if generated.returncode != 0:
            check(False, f"could not build a 3DES fixture: {generated.stderr.decode().strip()}")
        else:
            des3 = des3_path.read_bytes()
            check(
                serialization.load_pem_private_key(des3, password=PASSWORD.encode()) is not None,
                "cryptography reads the 3DES file (so it is a valid key file)",
            )
            proc = run(["import-pkcs8-encrypted", "--password", PASSWORD], stdin=des3)
            check(proc.returncode != 0, "we refuse the 3DES file")
            check(b"3DES" in proc.stderr, "and we name 3DES as the reason")

        sha1_path = pathlib.Path(tmp) / "sha1.pem"
        generated = subprocess.run(
            [
                "openssl", "pkcs8", "-topk8", "-in", str(src_path), "-out", str(sha1_path),
                "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA1", "-passout", f"pass:{PASSWORD}",
            ],
            capture_output=True,
        )
        if generated.returncode != 0:
            check(False, f"could not build a SHA-1 fixture: {generated.stderr.decode().strip()}")
        else:
            sha1 = sha1_path.read_bytes()
            check(
                serialization.load_pem_private_key(sha1, password=PASSWORD.encode()) is not None,
                "cryptography reads the HMAC-SHA1 file",
            )
            proc = run(["import-pkcs8-encrypted", "--password", PASSWORD], stdin=sha1)
            check(b"HMAC-SHA1" in proc.stderr, "we refuse it naming HMAC-SHA1")

        low_path = pathlib.Path(tmp) / "low.pem"
        subprocess.run(
            [
                "openssl", "pkcs8", "-topk8", "-in", str(src_path), "-out", str(low_path),
                "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256", "-iter", "1",
                "-passout", f"pass:{PASSWORD}",
            ],
            capture_output=True, check=True,
        )
        low = low_path.read_bytes()
        proc = run(["import-pkcs8-encrypted", "--password", PASSWORD], stdin=low)
        check(proc.returncode != 0 and b"below the minimum" in proc.stderr,
              "a 1-iteration file is refused as below the floor")

    print(f"\n{checks} checks, {len(failures)} failures")
    if failures:
        for failure in failures:
            print(f"  - {failure}")
        sys.exit(1)


if __name__ == "__main__":
    main()
