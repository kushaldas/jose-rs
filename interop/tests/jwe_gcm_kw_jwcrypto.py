#!/usr/bin/env python3
"""jwcrypto cross-check for AES-GCM key management (RFC 7518 §4.7).

`A128GCMKW`, `A192GCMKW` and `A256GCMKW` are the last key-management family that
needs neither an asymmetric key nor a password, and they are the family whose
header members collide with the envelope's own: RFC 7518 §4.7.1 names the key
wrap's IV and authentication tag `iv` and `tag`, which are also the names of the
RFC 7516 envelope members belonging to the *content* encryption. So these checks
are mostly about that collision, and about proving the header wrap really carries
the content CEK:

  * jwcrypto → jose-rs and jose-rs → jwcrypto, for all three algorithms;
  * both mandatory header members appear, in the integrity-protected header, at
    12 and 16 octets, and hold values *different* from the envelope's own `iv`/`tag`
    (a message that reused them would be a message nobody could read);
  * the conveyed encrypted key is unwrapped **in Python**, with the header's IV and
    tag, and yields a key of exactly `enc`'s CEK length — and using that recovered
    key, Python decrypts the content itself and recovers the plaintext. That is the
    statement "the key the header protects is the key the content needs" in a form
    that does not depend on either implementation's internals;
  * and a message edited in any of the four relevant places (header members,
    conveyed key, content) fails to decrypt on both sides.

Usage:

    ./interop/.venv/bin/python interop/tests/jwe_gcm_kw_jwcrypto.py
"""

import base64
import json
import os
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jwcrypto import jwe, jwk

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DEFAULT_HARNESS = os.path.join(
    ROOT, "interop", "rust-harness", "target", "release", "jose-interop"
)

ALGS = ["A128GCMKW", "A192GCMKW", "A256GCMKW"]
KEY_BITS = {"A128GCMKW": 128, "A192GCMKW": 192, "A256GCMKW": 256}
# CEK length per content algorithm (RFC 7518 §5): what the wrap must carry.
CEK_LEN = {"A128GCM": 16, "A256GCM": 32, "A128CBC-HS256": 32, "A256CBC-HS512": 64}
PLAINTEXT = b"AES-GCM key management, three implementations"

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
            err = json.loads(proc.stdout.decode())
            message = err.get("error", proc.stdout.decode()[:200])
        except Exception:
            message = (proc.stderr or proc.stdout).decode()[:200]
        raise AssertionError("harness %s failed: %s" % (" ".join(args), message))
    return json.loads(proc.stdout.decode())


def b64d(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def b64e(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def protected_header(token):
    return json.loads(b64d(token.split(".")[0]))


def jwcrypto_oct(alg):
    key = jwk.JWK(generate="oct", size=KEY_BITS[alg])
    key["alg"] = alg
    key["use"] = "enc"
    return key


def unwrap_in_python(alg, key_jwk, header, token):
    """Recover the CEK from the header's wrap, using only the RFC's rules."""
    kek = b64d(key_jwk["k"])
    iv = b64d(header["iv"])
    tag = b64d(header["tag"])
    wrapped = b64d(token.split(".")[1])
    # RFC 7518 §4.7.1: the IV is the 96 bits, the tag is the 128 bits, and the
    # ciphertext is the conveyed key. `cryptography`'s AESGCM takes ciphertext||tag.
    return AESGCM(kek).decrypt(iv, wrapped + tag, b"")


def main(harness_path):
    for alg in ALGS:
        for enc in ["A128GCM", "A256GCM", "A128CBC-HS256", "A256CBC-HS512"]:
            # ---- jwcrypto → jose-rs ---------------------------------------
            key = jwcrypto_oct(alg)
            token = jwe.JWE(
                PLAINTEXT, protected={"alg": alg, "enc": enc}
            )
            token.add_recipient(key)
            serialized = token.serialize(compact=True)
            header = protected_header(serialized)
            check(
                "%s/%s jwcrypto emits both members in the protected header" % (alg, enc),
                "iv" in header and "tag" in header,
                json.dumps(header),
            )
            check(
                "%s/%s the members have the RFC sizes" % (alg, enc),
                len(b64d(header.get("iv", ""))) == 12
                and len(b64d(header.get("tag", ""))) == 16,
                json.dumps(header),
            )
            out = harness(
                harness_path,
                ["decrypt-compact", "--alg", alg, "--enc", enc],
                # For `oct` there is no separate private part: `export()` yields the
                # JWK including `k`, which is what the consumer needs.
                {"jwk": json.loads(key.export()), "jwe": serialized},
            )
            check(
                "%s/%s jose-rs reads jwcrypto's message" % (alg, enc),
                b64d(out["plaintext_b64u"]) == PLAINTEXT,
            )

            # ---- jose-rs → jwcrypto ---------------------------------------
            rs_key = harness(harness_path, ["gen-key", "--alg", alg, "--enc", enc], {})
            made = harness(
                harness_path,
                ["encrypt-compact", "--alg", alg, "--enc", enc],
                {"jwk": rs_key, "plaintext_b64u": b64e(PLAINTEXT), "header": {}},
            )["jwe"]
            rs_header = protected_header(made)
            check(
                "%s/%s jose-rs emits both members in the protected header" % (alg, enc),
                "iv" in rs_header and "tag" in rs_header,
                json.dumps(rs_header),
            )
            check(
                "%s/%s jose-rs matches jwcrypto's shape exactly" % (alg, enc),
                set(rs_header) == set(header),
                "%s vs %s" % (sorted(rs_header), sorted(header)),
            )
            # The envelope's own members must be different values, not echoes.
            check(
                "%s/%s the wrap's iv/tag differ from the envelope's" % (alg, enc),
                rs_header["iv"] != made.split(".")[2]
                and rs_header["tag"] != made.split(".")[4],
            )
            receiver = jwk.JWK(**rs_key)
            read = jwe.JWE()
            read.deserialize(made, key=receiver)
            check(
                "%s/%s jwcrypto reads jose-rs's message" % (alg, enc),
                read.payload == PLAINTEXT,
            )

            # ---- the header wrap really carries the content CEK ----------
            cek = unwrap_in_python(alg, rs_key, rs_header, made)
            check(
                "%s/%s the wrap carries exactly enc's CEK length" % (alg, enc),
                len(cek) == CEK_LEN[enc],
                "%d bytes, %s wants %d" % (len(cek), enc, CEK_LEN[enc]),
            )
            # And using *only* that recovered key, Python decrypts the content: the
            # two-stage key chain is verified end to end, not just decrypted.
            content_iv = b64d(made.split(".")[2])
            content_ct = b64d(made.split(".")[3])
            content_tag = b64d(made.split(".")[4])
            aad = made.split(".")[0].encode()
            recovered = decrypt_content(
                cek, enc, content_iv, content_ct, content_tag, made.split(".")[0]
            )
            check(
                "%s/%s the recovered CEK decrypts the content" % (alg, enc),
                recovered == PLAINTEXT,
                "got %r" % (recovered,),
            )

            # ---- edits must fail ------------------------------------------
            check(
                "%s/%s a conveyed key edited in place fails" % (alg, enc),
                decrypt_fails(harness_path, rs_key, alg, enc, made, which="key"),
            )
            check(
                "%s/%s a header iv edited in place fails" % (alg, enc),
                decrypt_fails(harness_path, rs_key, alg, enc, made, which="iv"),
            )

        # ---- a key of the wrong size is refused, not truncated -----------
        rs_key = harness(harness_path, ["gen-key", "--alg", "A128GCMKW", "--enc", "A128GCM"], {})
        wrong = dict(rs_key)
        wrong["k"] = b64e(b64d(rs_key["k"]) + b"\x00" * 16)  # 32 bytes for A128GCMKW
        try:
            harness(
                harness_path,
                ["encrypt-compact", "--alg", "A128GCMKW", "--enc", "A128GCM"],
                {"jwk": wrong, "plaintext_b64u": b64e(PLAINTEXT), "header": {}},
            )
            check("A128GCMKW with a 256-bit key is refused", False, "it encrypted anyway")
        except AssertionError as exc:
            check(
                "A128GCMKW with a 256-bit key is refused",
                "KEK must be" in str(exc),
                str(exc)[:120],
            )

    print("checks passed: %d" % PASS)
    for failure in FAIL:
        print("FAIL: %s" % failure)
    return 1 if FAIL else 0


def decrypt_content(cek, enc, iv, ciphertext, tag, aad):
    """Content decryption per RFC 7518 §5, so the CEK check is not circular."""
    if enc in ("A128GCM", "A256GCM"):
        # RFC 7516 §7.1: the AAD input for the compact form is the ASCII bytes of
        # the base64url protected header, not the decoded JSON.
        return AESGCM(cek).decrypt(iv, ciphertext + tag, aad.encode())
    # CBC-HMAC (RFC 7518 §5.2.2.1): the CEK splits into MAC key || encryption key
    # — "note that the MAC key comes before the encryption key … in the opposite
    # order of the algorithm names" — and the MAC is
    #     HMAC(MAC_KEY, A || IV || E || AL)
    # with A the ASCII of the base64url protected header and AL its 64-bit bit
    # count, appended **last** (the illustration at the end of §5.2.2.1, not the
    # prose list, gives the order). Getting it wrong still decrypts fine locally,
    # which is the point of computing it independently here.
    half = len(cek) // 2
    mac_key, enc_key = cek[:half], cek[half:]
    import hashlib
    import hmac as _hmac
    import struct

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    algo = hashlib.sha256 if enc == "A128CBC-HS256" else hashlib.sha512
    aad_bytes = aad.encode()
    message = aad_bytes + iv + ciphertext + struct.pack(">Q", len(aad_bytes) * 8)
    # The tag is the MAC output truncated to the length `enc` declares, which is
    # exactly what the envelope's tag segment holds.
    expected = _hmac.new(mac_key, message, algo).digest()[: len(tag)]
    if expected != tag:
        return None
    dec = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    pad = padded[-1]
    return padded[:-pad]


def decrypt_fails(harness_path, key, alg, enc, token, which):
    parts = token.split(".")
    if which == "key":
        raw = bytearray(b64d(parts[1]))
        raw[0] ^= 0x01
        parts[1] = b64e(bytes(raw))
    else:
        header = protected_header(token)
        raw = bytearray(b64d(header["iv"]))
        raw[0] ^= 0x01
        header["iv"] = b64e(bytes(raw))
        parts[0] = b64e(json.dumps(header, separators=(",", ":")).encode())
    try:
        harness(
            harness_path,
            ["decrypt-compact", "--alg", alg, "--enc", enc],
            {"jwk": key, "jwe": ".".join(parts)},
        )
        return False
    except AssertionError:
        return True


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HARNESS))
