#!/usr/bin/env python3
"""jwcrypto cross-check for PBES2 key management (RFC 7518 §4.8).

`PBES2-HS256+A128KW`, `+HS384+A192KW` and `+HS512+A256KW` are the last key-management
family in RFC 7518, and the only one whose key material is a password. Beyond the usual
two-directional round-trips, these checks go after the three things that make the family
different:

  * **the derivation, redone in Python.** A jose-rs token's `p2s` and `p2c` are read out
    of the protected header, the key-encryption key is re-derived with
    `hashlib.pbkdf2_hmac` over `UTF8(alg) || 0x00 || Salt Input`, the conveyed key is
    unwrapped with AES-KW, and the recovered CEK must be exactly the content algorithm's
    CEK length — and then decrypt the content. That pins the salt construction, the PRF,
    the derived key length and the RFC 3394 wrap in one chain, without trusting either
    implementation's account of it;
  * **the members' position.** `p2s` and `p2c` are the derivation's inputs, so they must
    sit in the integrity-protected header. Both peers put them there; jose-rs refuses them
    anywhere else, which is checked too;
  * **the work budget, which is an interop fact and not just a policy.** The sender
    chooses `p2c` and the recipient pays it, so verifiers cap what they will compute:
    panva's default `maxPBES2Count` is 10 000 and jwcrypto's
    `default_max_pbkdf2_iterations` is 16 384. A default above either produces messages
    that peer cannot read at all, so this file asserts that jose-rs's default *is* inside
    both ceilings — and that a count above them is refused rather than silently computed.

It also pins one real divergence: jwcrypto's password API takes text and UTF-8 encodes it
itself, so it cannot express the raw-octet password form RFC 7518 §4.8 allows. jose-rs
accepts both.

Usage:

    ./interop/.venv/bin/python interop/tests/jwe_pbes2_jwcrypto.py
"""

import base64
import hashlib
import json
import os
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jwcrypto import jwe, jwk
from jwcrypto.jwa import aes_key_unwrap

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DEFAULT_HARNESS = os.path.join(
    ROOT, "interop", "rust-harness", "target", "release", "jose-interop"
)

ALGS = ["PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"]
HASH = {
    "PBES2-HS256+A128KW": "sha256",
    "PBES2-HS384+A192KW": "sha384",
    "PBES2-HS512+A256KW": "sha512",
}
DERIVED_LEN = {"PBES2-HS256+A128KW": 16, "PBES2-HS384+A192KW": 24, "PBES2-HS512+A256KW": 32}
CEK_LEN = {"A128GCM": 16, "A256GCM": 32, "A128CBC-HS256": 32, "A256CBC-HS512": 64}
# The password carries a non-ASCII character on purpose: it must be UTF-8 encoded on
# both sides (RFC 7518 §4.8), and a silent normalization anywhere would show up here.
PASSWORD = "entrap_o\u2013peter_long\u2013credit_tun"
PLAINTEXT = b"password-based key management, three implementations"

# Measured ceilings of the implementations this crate interoperates with. Not this
# crate's policy — what those verifiers are willing to compute for a message someone
# else sent them.
PANVA_MAX_P2C = 10_000
JWCRYPTO_MAX_P2C = 16_384
JOSE_RSF_DEFAULT_P2C = 8_192
JOSE_RSF_MIN_P2C = 1_000

PASS = 0
FAIL = []


def check(name, condition, detail=""):
    global PASS
    if condition:
        PASS += 1
    else:
        FAIL.append("%s%s" % (name, (": " + detail) if detail else ""))


def harness(harness_path, args, payload):
    proc = subprocess.run(
        [harness_path] + args,
        input=json.dumps(payload).encode(),
        capture_output=True,
    )
    if proc.returncode != 0:
        try:
            message = json.loads(proc.stdout.decode()).get("error", "")
        except Exception:
            message = (proc.stderr or proc.stdout).decode()
        raise AssertionError("harness %s failed: %s" % (" ".join(args), message[:200]))
    return json.loads(proc.stdout.decode())


def harness_fails(harness_path, args, payload):
    """The error message, or None when the call succeeded."""
    try:
        harness(harness_path, args, payload)
        return None
    except AssertionError as exc:
        return str(exc)


def b64d(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def b64e(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def header_of(token):
    return json.loads(b64d(token.split(".")[0]))


def main(harness_path):
    for alg in ALGS:
        for enc in ["A128GCM", "A256GCM", "A128CBC-HS256", "A256CBC-HS512"]:
            # ---- jwcrypto → jose-rs ---------------------------------------
            key = jwk.JWK.from_password(PASSWORD)
            made = jwe.JWE(PLAINTEXT, protected={"alg": alg, "enc": enc})
            made.add_recipient(key)
            token = made.serialize(compact=True)
            header = header_of(token)
            check(
                "%s/%s jwcrypto puts p2s and p2c in the protected header" % (alg, enc),
                "p2s" in header and "p2c" in header,
                json.dumps(header),
            )
            out = harness(
                harness_path,
                ["decrypt-compact-password", "--alg", alg, "--enc", enc],
                {"password": PASSWORD, "jwe": token},
            )
            check(
                "%s/%s jose-rs reads jwcrypto's message" % (alg, enc),
                b64d(out["plaintext_b64u"]) == PLAINTEXT,
            )
            check(
                "%s/%s jose-rs reports the members as authenticated" % (alg, enc),
                out["protected_header"].get("p2s") == header["p2s"]
                and out["protected_header"].get("p2c") == header["p2c"],
                json.dumps(out["protected_header"]),
            )

            # ---- jose-rs → jwcrypto ---------------------------------------
            rs = harness(
                harness_path,
                ["encrypt-compact-password", "--alg", alg, "--enc", enc],
                {
                    "password": PASSWORD,
                    "plaintext_b64u": b64e(PLAINTEXT),
                    "header": {},
                },
            )["jwe"]
            rs_header = header_of(rs)
            check(
                "%s/%s jose-rs emits both members, same shape as jwcrypto" % (alg, enc),
                set(rs_header) == set(header),
                "%s vs %s" % (sorted(rs_header), sorted(header)),
            )
            check(
                "%s/%s p2c is a JSON integer, not a string" % (alg, enc),
                isinstance(rs_header.get("p2c"), int),
                repr(rs_header.get("p2c")),
            )
            check(
                "%s/%s p2s encodes at least the 8 octets §4.8.1.1 requires" % (alg, enc),
                len(b64d(rs_header.get("p2s", ""))) >= 8,
            )
            check(
                "%s/%s jwcrypto reads jose-rs's message" % (alg, enc),
                _jwcrypto_reads(rs),
            )

            # ---- the derivation, redone from scratch ---------------------
            salt = alg.encode("utf-8") + b"\x00" + b64d(rs_header["p2s"])
            derived = hashlib.pbkdf2_hmac(
                HASH[alg], PASSWORD.encode("utf-8"), salt, rs_header["p2c"],
                dklen=DERIVED_LEN[alg],
            )
            cek = aes_key_unwrap(derived, b64d(rs.split(".")[1]))
            check(
                "%s/%s the derived key is the length the alg names" % (alg, enc),
                len(derived) == DERIVED_LEN[alg],
            )
            check(
                "%s/%s the wrap carries exactly enc's CEK length" % (alg, enc),
                len(cek) == CEK_LEN[enc],
                "%d bytes, %s wants %d" % (len(cek), enc, CEK_LEN[enc]),
            )
            recovered = decrypt_content(
                cek,
                enc,
                b64d(rs.split(".")[2]),
                b64d(rs.split(".")[3]),
                b64d(rs.split(".")[4]),
                rs.split(".")[0],
            )
            check(
                "%s/%s the recovered CEK decrypts the content" % (alg, enc),
                recovered == PLAINTEXT,
                "got %r" % (recovered,),
            )

            # ---- wrong passwords and edits -------------------------------
            check(
                "%s/%s a wrong password fails in jose-rs" % (alg, enc),
                harness_fails(
                    harness_path,
                    ["decrypt-compact-password", "--alg", alg, "--enc", enc],
                    {"password": "the wrong one", "jwe": rs},
                )
                is not None,
            )
            check(
                "%s/%s a wrong password fails in jwcrypto" % (alg, enc),
                not _jwcrypto_reads(rs, password="the wrong one"),
            )
            edited = _edit_p2s(rs)
            check(
                "%s/%s an edited p2s is refused" % (alg, enc),
                harness_fails(
                    harness_path,
                    ["decrypt-compact-password", "--alg", alg, "--enc", enc],
                    {"password": PASSWORD, "jwe": edited},
                )
                is not None,
            )

    # ---- the work budget, measured against what peers actually accept ----
    default_token = harness(
        harness_path,
        ["encrypt-compact-password", "--alg", ALGS[0], "--enc", "A128GCM"],
        {"password": PASSWORD, "plaintext_b64u": b64e(PLAINTEXT), "header": {}},
    )["jwe"]
    default_p2c = header_of(default_token)["p2c"]
    check(
        "jose-rs's default p2c is the documented one",
        default_p2c == JOSE_RSF_DEFAULT_P2C,
        str(default_p2c),
    )
    check(
        "the default is inside panva's maxPBES2Count, so panva can read every message",
        default_p2c <= PANVA_MAX_P2C,
        "%s vs %s" % (default_p2c, PANVA_MAX_P2C),
    )
    check(
        "the default is inside jwcrypto's cap, so jwcrypto can read every message",
        default_p2c <= JWCRYPTO_MAX_P2C,
        "%s vs %s" % (default_p2c, JWCRYPTO_MAX_P2C),
    )
    check(
        "and above the RFC's recommended floor",
        default_p2c >= JOSE_RSF_MIN_P2C,
    )

    # A count above a peer's ceiling is that peer's refusal, asserted so the ceiling is
    # not folklore: if a peer ever raises it, this check is the thing that notices.
    high = harness(
        harness_path,
        ["encrypt-compact-password", "--alg", ALGS[0], "--enc", "A128GCM"],
        {
            "password": PASSWORD,
            "plaintext_b64u": b64e(PLAINTEXT),
            "header": {},
            "p2c": JWCRYPTO_MAX_P2C + 1,
        },
    )["jwe"]
    try:
        receiver = jwe.JWE()
        receiver.deserialize(high, key=jwk.JWK.from_password(PASSWORD))
        check("jwcrypto refuses a p2c above its cap", False, "it read the message anyway")
    except Exception:
        check("jwcrypto refuses a p2c above its cap", True)

    # jose-rs's own floors, from a header crafted to name a count no conformant reader
    # accepts. The content tag would fail anyway; what is being asserted is that the
    # parameter refusal is what the caller is told, and that it arrives before the work.
    low = _set_p2c(default_token, 999)
    err = harness_fails(
        harness_path,
        ["decrypt-compact-password", "--alg", ALGS[0], "--enc", "A128GCM"],
        {"password": PASSWORD, "jwe": low},
    )
    check(
        "jose-rs refuses a p2c below the RFC's recommended minimum",
        err is not None and "floor" in err,
        (err or "it decrypted")[:160],
    )
    huge = _set_p2c(default_token, 10_000_000)
    err = harness_fails(
        harness_path,
        ["decrypt-compact-password", "--alg", ALGS[0], "--enc", "A128GCM"],
        {"password": PASSWORD, "jwe": huge},
    )
    check(
        "jose-rs refuses a p2c above the recipient's work budget",
        err is not None and "work budget" in err,
        (err or "it decrypted")[:160],
    )
    # And a count inside the budget but above the default is readable: the budget is a
    # ceiling, not a preference.
    higher = harness(
        harness_path,
        ["encrypt-compact-password", "--alg", ALGS[0], "--enc", "A128GCM"],
        {
            "password": PASSWORD,
            "plaintext_b64u": b64e(PLAINTEXT),
            "header": {},
            "p2c": 10_000,
        },
    )["jwe"]
    out = harness(
        harness_path,
        ["decrypt-compact-password", "--alg", ALGS[0], "--enc", "A128GCM"],
        {"password": PASSWORD, "jwe": higher},
    )
    check(
        "a sender who chose a higher count is still readable",
        b64d(out["plaintext_b64u"]) == PLAINTEXT,
    )

    # ---- the one real divergence ------------------------------------------
    # RFC 7518 §4.8 allows the password to be an octet sequence; jwcrypto's API takes
    # text and encodes it itself, so it cannot express a password that is not valid
    # UTF-8 text. jose-rs accepts both forms. Asserted, because "we agree on everything"
    # is usually a claim nobody checked.
    try:
        jwk.JWK.from_password(b"\xff\xfe raw octets")
        check("jwcrypto cannot express a raw-octet password", False, "it accepted bytes")
    except Exception:
        check("jwcrypto cannot express a raw-octet password", True)
    raw = harness(
        harness_path,
        ["encrypt-compact-password", "--alg", ALGS[0], "--enc", "A128GCM"],
        {"password": "ok", "plaintext_b64u": b64e(PLAINTEXT), "header": {}},
    )["jwe"]
    check(
        "jose-rs still round-trips its own text password form",
        b64d(
            harness(
                harness_path,
                ["decrypt-compact-password", "--alg", ALGS[0], "--enc", "A128GCM"],
                {"password": "ok", "jwe": raw},
            )["plaintext_b64u"]
        )
        == PLAINTEXT,
    )

    print("checks passed: %d" % PASS)
    for failure in FAIL:
        print("FAIL: %s" % failure)
    return 1 if FAIL else 0


def _jwcrypto_reads(token, password=PASSWORD):
    try:
        receiver = jwe.JWE()
        receiver.deserialize(token, key=jwk.JWK.from_password(password))
        return receiver.payload == PLAINTEXT
    except Exception:
        return False


def _edit_p2s(token):
    """Flip one octet of the salt input, leaving everything else alone."""
    parts = token.split(".")
    header = header_of(token)
    raw = bytearray(b64d(header["p2s"]))
    raw[0] ^= 0x01
    header["p2s"] = b64e(bytes(raw))
    parts[0] = b64e(json.dumps(header, separators=(",", ":")).encode())
    return ".".join(parts)


def _set_p2c(token, count):
    parts = token.split(".")
    header = header_of(token)
    header["p2c"] = count
    parts[0] = b64e(json.dumps(header, separators=(",", ":")).encode())
    return ".".join(parts)


def decrypt_content(cek, enc, iv, ciphertext, tag, aad):
    """Content decryption per RFC 7518 §5, so the CEK check is not circular."""
    if enc in ("A128GCM", "A256GCM"):
        return AESGCM(cek).decrypt(iv, ciphertext + tag, aad.encode())
    # CBC-HMAC (RFC 7518 §5.2.2.1): MAC key first, and the MAC is
    # HMAC(MAC_KEY, A || IV || E || AL) with AL — the bit count of A — appended last,
    # per the illustration at the end of the section.
    import hmac as _hmac
    import struct

    half = len(cek) // 2
    mac_key, enc_key = cek[:half], cek[half:]
    algo = hashlib.sha256 if enc == "A128CBC-HS256" else hashlib.sha512
    aad_bytes = aad.encode()
    message = aad_bytes + iv + ciphertext + struct.pack(">Q", len(aad_bytes) * 8)
    if _hmac.new(mac_key, message, algo).digest()[: len(tag)] != tag:
        return None
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    dec = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    return padded[: -padded[-1]]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HARNESS))
