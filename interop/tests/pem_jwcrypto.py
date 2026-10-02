#!/usr/bin/env python3
"""PEM (RFC 7468) import/export cross-check for JWKs — I0, ADR 0022.

PEM is where an implementation decides how strict it wants to be, so these checks are
deliberately weighted toward the label and the armor rather than toward the DER:

  * **Python → Rust.** `cryptography` generates RSA-2048 / P-256 / P-384 / P-521 / Ed25519
    keys and exports PKCS#8 and SPKI PEM. jose-rs imports them, and the resulting JWK is
    compared member by member against values computed *here* from the key object — the
    fixed-width coordinates, the minimal-width RSA integers — so an import that guessed at
    a width or a sign would show up. Then jose-rs signs with the imported key and Python
    verifies with the SPKI public half.
  * **Rust → Python.** jose-rs generates keys, exports `PRIVATE KEY` / `PUBLIC KEY` PEM,
    and `cryptography` loads them. `openssl pkey` re-encodes the same key and the two byte
    strings must match, which pins canonical DER rather than "some file that parses".
  * **Strictness, both directions.** A PKCS#1, SEC1, certificate, encrypted or
    legacy-header block is refused with the label named; two blocks are refused with a
    count; text before `-----BEGIN` and text after `-----END` are refused while
    surrounding whitespace is accepted. The refusals matter because the permissive
    alternative — sniff the bytes and guess the structure — is what makes a key file
    ambiguous.

Usage:

    ./interop/.venv/bin/python interop/tests/pem_jwcrypto.py [path-to-jose-interop]
"""

import base64
import json
import os
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_HARNESS = os.path.join(
    ROOT, "interop", "rust-harness", "target", "release", "jose-interop"
)

PASS = 0
FAIL = []


def check(name, condition, detail=""):
    global PASS
    if condition:
        PASS += 1
    else:
        FAIL.append("%s%s" % (name, (": " + detail) if detail else ""))


def harness_raw(harness_path, args, stdin_bytes):
    """Run the harness with raw (non-JSON) stdin, returning (ok, stdout, stderr)."""
    proc = subprocess.run([harness_path] + args, input=stdin_bytes, capture_output=True)
    out = proc.stdout.decode(errors="replace")
    err = proc.stderr.decode(errors="replace")
    return proc.returncode == 0, out, err


def harness_ok(harness_path, args, stdin_bytes):
    ok, out, err = harness_raw(harness_path, args, stdin_bytes)
    if not ok:
        raise AssertionError(
            "harness %s failed: %s" % (" ".join(args), (err or out)[:300])
        )
    return out


def harness_fails(harness_path, args, stdin_bytes, must_say):
    """Require the harness to refuse, and to say why in a way the caller can act on."""
    ok, out, err = harness_raw(harness_path, args, stdin_bytes)
    message = (err or out).strip()
    if ok:
        return False, "accepted after %s: %s" % (" ".join(args), message[:200])
    for fragment in must_say:
        if fragment not in message:
            return False, "refused without naming %r: %s" % (fragment, message[:220])
    return True, ""


def b64e(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def i2b(n, width=None):
    """RFC 7518 base64url of a big integer: minimal width, unless the member is fixed."""
    length = width if width else (n.bit_length() + 7) // 8
    return b64e(n.to_bytes(length, "big"))


def expected_jwk_from_python(key, include_private):
    """The JWK `cryptography`'s key object *should* correspond to, computed independently."""
    # Public keys are their own public half; private keys have to say so.
    pub = key.public_key() if hasattr(key, "public_key") else key
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        numbers = pub.public_numbers()
        jwk = {"kty": "RSA", "n": i2b(numbers.n), "e": i2b(numbers.e)}
        if include_private:
            priv = key.private_numbers()
            jwk["d"] = i2b(priv.d)
            jwk["p"] = i2b(priv.p)
            jwk["q"] = i2b(priv.q)
    elif isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        numbers = pub.public_numbers()
        sizes = {
            "secp256r1": ("P-256", 32),
            "secp384r1": ("P-384", 48),
            "secp521r1": ("P-521", 66),
        }
        crv, width = sizes[pub.curve.name]
        jwk = {"kty": "EC", "crv": crv, "x": i2b(numbers.x, width), "y": i2b(numbers.y, width)}
        if include_private:
            d = key.private_numbers().private_value
            jwk["d"] = i2b(d, width)
    elif isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        raw = pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64e(raw)}
        if include_private:
            jwk["d"] = b64e(
                key.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            )
    else:
        raise AssertionError("unexpected key type %r" % type(key))
    return jwk


def subset_match(got, want, members):
    bad = [m for m in members if got.get(m) != want.get(m)]
    return bad


PRIVATE_FORMAT = serialization.PrivateFormat.PKCS8
PUBLIC_FORMAT = serialization.PublicFormat.SubjectPublicKeyInfo
NO_ENC = serialization.NoEncryption()


def make_keys():
    return {
        "RSA-2048": rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        ),
        "P-256": ec.generate_private_key(ec.SECP256R1(), default_backend()),
        "P-384": ec.generate_private_key(ec.SECP384R1(), default_backend()),
        "P-521": ec.generate_private_key(ec.SECP521R1(), default_backend()),
        "Ed25519": ed25519.Ed25519PrivateKey.generate(),
    }


def pem_of(key, private=True):
    fmt = PRIVATE_FORMAT if private else PUBLIC_FORMAT
    enc = NO_ENC
    return key.private_bytes(serialization.Encoding.PEM, fmt, enc) if private else key.public_key().public_bytes(serialization.Encoding.PEM, fmt)


SIGN_ALG = {"RSA-2048": "RS256", "P-256": "ES256", "P-384": "ES384", "P-521": "ES512", "Ed25519": "EdDSA"}


def verify_in_python(name, public_pem, token):
    """Verify the JWS jose-rs produced, using `cryptography` as the independent verifier."""
    header_b64, payload_b64, sig_b64 = token.split(".")
    signing_input = (header_b64 + "." + payload_b64).encode()
    sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    key = serialization.load_pem_public_key(public_pem, backend=default_backend())
    if name == "Ed25519":
        key.verify(sig, signing_input)
    elif name == "RSA-2048":
        key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
    else:
        # JWS carries concatenated r||s; `cryptography` wants DER.
        half = len(sig) // 2
        r = int.from_bytes(sig[:half], "big")
        s = int.from_bytes(sig[half:], "big")
        der = encode_dss(r, s)
        key.verify(der, signing_input, ec.ECDSA(hashes.SHA256() if name == "P-256" else (hashes.SHA384() if name == "P-384" else hashes.SHA512())))
    return True


def der_len(n):
    """DER length: short form below 0x80, long form above (P-521 signatures need it)."""
    if n < 0x80:
        return bytes([n])
    encoded = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def encode_dss(r, s):
    def der_int(value):
        raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return b"\x02" + der_len(len(raw)) + raw

    body = der_int(r) + der_int(s)
    return b"\x30" + der_len(len(body)) + body


def openssl(args, data):
    proc = subprocess.run(
        ["openssl"] + args, input=data, capture_output=True
    )
    return proc.returncode == 0, proc.stdout, proc.stderr


def main(harness_path):
    keys = make_keys()

    # ---------------------------------------------------------------- Python → Rust
    for name, key in keys.items():
        private_pem = pem_of(key, private=True)
        public_pem = pem_of(key, private=False)

        ok, out, err = harness_raw(harness_path, ["import-pem"], private_pem)
        if not ok:
            FAIL.append("%s: jose-rs refused a PKCS#8 PEM from cryptography: %s" % (name, (err or out)[:200]))
            continue
        imported = json.loads(out)
        want = expected_jwk_from_python(key, include_private=True)
        members = sorted(want.keys())
        bad = subset_match(imported, want, members)
        check(
            "%s import matches the key cryptography generated" % name,
            not bad,
            "members differ: %s" % ", ".join(bad),
        )

        ok, out, err = harness_raw(harness_path, ["import-pem"], public_pem)
        if not ok:
            FAIL.append("%s: jose-rs refused an SPKI PEM: %s" % (name, (err or out)[:200]))
            continue
        imported_pub = json.loads(out)
        want_pub = expected_jwk_from_python(key, include_private=False)
        bad = subset_match(imported_pub, want_pub, sorted(want_pub.keys()))
        check("%s SPKI import is the public half" % name, not bad, "differ: %s" % bad)
        check(
            "%s SPKI import carries no private part" % name,
            "d" not in imported_pub,
            json.dumps(sorted(imported_pub.keys())),
        )

        # …and the imported key signs something Python can verify with the *other* file.
        ok, out, err = harness_raw(
            harness_path, ["sign-pem", "--alg", SIGN_ALG[name]], private_pem
        )
        if not ok:
            FAIL.append("%s: signing with an imported key failed: %s" % (name, (err or out)[:200]))
            continue
        try:
            verify_in_python(name, public_pem, out.strip())
            check("%s signs with a key read from another implementation's PEM" % name, True)
        except Exception as exc:
            check("%s signs with a key read from another implementation's PEM" % name, False, str(exc)[:200])

    # ------------------------------------------------------------------ Rust → Python
    for alg, crv in [("RS256", None), ("ES256", None), ("ES384", None), ("EdDSA", None)]:
        gen_args = ["gen-key", "--alg", alg]
        jwk_json = harness_ok(harness_path, gen_args, b"")
        rust_key = json.loads(jwk_json)

        priv_pem = harness_ok(harness_path, ["export-pem", "--pem=private"], jwk_json.encode())
        pub_pem = harness_ok(harness_path, ["export-pem", "--pem=public"], jwk_json.encode())
        check(
            "%s exports exactly the two labels" % alg,
            priv_pem.startswith("-----BEGIN PRIVATE KEY-----")
            and pub_pem.startswith("-----BEGIN PUBLIC KEY-----"),
            priv_pem[:40] + " / " + pub_pem[:40],
        )

        # `cryptography` must be able to load both.
        try:
            loaded = serialization.load_pem_private_key(
                priv_pem.encode(), password=None, backend=default_backend()
            )
            loaded_pub = serialization.load_pem_public_key(
                pub_pem.encode(), backend=default_backend()
            )
            check("%s PEM loads in cryptography" % alg, True)
        except Exception as exc:
            check("%s PEM loads in cryptography" % alg, False, str(exc)[:200])
            continue

        # The exported JWK-shaped facts must agree with what Rust said.
        want = expected_jwk_from_python(loaded, include_private=True)
        bad = subset_match(rust_key, want, ["kty", "n", "e", "d", "crv", "x", "y"])
        check(
            "%s private PEM is the key the JWK describes" % alg,
            not bad,
            "differ: %s" % bad,
        )
        want_pub = expected_jwk_from_python(loaded_pub, include_private=False)
        bad = subset_match(rust_key, want_pub, ["kty", "n", "e", "crv", "x", "y"])
        check("%s public PEM is the public half" % alg, not bad, "differ: %s" % bad)

        # OpenSSL re-encodes the same key identically: canonical DER, not just parseable.
        ok, o_repub, oerr = openssl(["pkey", "-pubin", "-pubout"], pub_pem.encode())
        check(
            "%s public PEM is what openssl emits for the same key" % alg,
            ok and o_repub == pub_pem.encode(),
            ((oerr or b"")[:160].decode(errors="replace") if not ok else "bytes differ"),
        )
        ok, o_repriv, oerr = openssl(["pkcs8", "-topk8", "-nocrypt"], priv_pem.encode())
        check(
            "%s private PEM is what openssl emits for the same key" % alg,
            ok and o_repriv == priv_pem.encode(),
            ((oerr or b"")[:160].decode(errors="replace") if not ok else "bytes differ"),
        )

    # X25519: no SPKI in this backend, and the refusal has to be by name rather than a
    # file that claims a structure it does not have.
    x = harness_ok(harness_path, ["gen-key", "--alg", "ECDH-ES", "--crv", "X25519"], b"")
    ok, out, err = harness_raw(harness_path, ["export-pem", "--pem=public"], x.encode())
    check(
        "X25519 public export is refused by name",
        not ok and "X25519" in (err or out) and "SPKI" in (err or out),
        (err or out)[:200],
    )

    # ------------------------------------------------------------------- strictness
    refuser = ["import-pem"]
    samples = []

    # PKCS#1 and SEC1 blocks, generated here so they are independent of the repo fixtures.
    rsa_key = keys["RSA-2048"]
    pkcs1 = rsa_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        NO_ENC,
    )
    samples.append(("PKCS#1 block", pkcs1, ["RSA PRIVATE KEY", "PKCS#1"]))

    ec_key = keys["P-256"]
    sec1 = ec_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        NO_ENC,
    )
    samples.append(("SEC1 block", sec1, ["EC PRIVATE KEY", "SEC1"]))

    # A self-signed certificate wrapping the public key: a certificate, not a key.
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"jose-rs interop")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(rsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(rsa_key, hashes.SHA256(), backend=default_backend())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    samples.append(("certificate block", cert_pem, ["CERTIFICATE", "certificate"]))

    # A password-encrypted PKCS#8 (RFC 5958): labeled ENCRYPTED PRIVATE KEY.
    encrypted = rsa_key.private_bytes(
        serialization.Encoding.PEM,
        PRIVATE_FORMAT,
        serialization.BestAvailableEncryption(b"correct horse"),
    )
    samples.append(("encrypted PKCS#8", encrypted, ["ENCRYPTED PRIVATE KEY"]))

    # Legacy RFC 1423 armor (Proc-Type / DEK-Info), via the openssl CLI.
    ok, legacy, _ = openssl(
        ["rsa", "-traditional", "-aes256", "-passout", "pass:hunter2"],
        pem_of(rsa_key),
    )
    if ok and b"DEK-Info" in legacy:
        samples.append(("legacy DEK-Info block", legacy, ["password-encrypted"]))

    for label, text, must_say in samples:
        refused, why = harness_fails(harness_path, refuser, text, must_say)
        check("%s is refused with the reason named" % label, refused, why)

    # Armor-level refusals, assembled here rather than shipped as fixtures.
    ed_pub = pem_of(keys["Ed25519"], private=False)
    armor_cases = [
        ("two blocks in one file", ed_pub + ed_pub, ["2 blocks"]),
        ("text before the key", b"subject: your key\n\n" + ed_pub, ["before the"]),
        ("text after the key", ed_pub + b"thanks\n", ["after the"]),
        ("lowercase label", ed_pub.replace(b"PUBLIC KEY", b"public key"), ["block"]),
        ("JWK JSON, not PEM", json.dumps({"kty": "oct", "k": "AAAA"}).encode(), ["PEM"]),
        # Re-indented armor (a key pasted out of a document) is *inside* the block, so it
        # is not "whitespace around the block": strict RFC 7468 refuses it, and so do we.
        ("re-indented block", b"  " + ed_pub.replace(b"\n", b"\n  "), ["PEM"]),
    ]
    for label, text, must_say in armor_cases:
        refused, why = harness_fails(harness_path, refuser, text, must_say)
        check("%s is refused" % label, refused, why)

    # …and the things that are *not* refusals, because whitespace is how files get saved.
    for label, text in [
        ("leading blank lines", b"\n\n" + ed_pub),
        ("trailing blank lines", ed_pub + b"\n\n   \n"),
        ("CRLF line endings", ed_pub.replace(b"\n", b"\r\n")),
        ("no final newline", ed_pub.rstrip(b"\n")),
    ]:
        ok, out, err = harness_raw(harness_path, refuser, text)
        check("%s is accepted" % label, ok, (err or out)[:200])

    print("PEM interop checks passed: %d" % PASS)
    if FAIL:
        print("FAILURES (%d):" % len(FAIL))
        for f in FAIL:
            print("  - " + f)
        return 1
    return 0


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HARNESS
    sys.exit(main(path))
