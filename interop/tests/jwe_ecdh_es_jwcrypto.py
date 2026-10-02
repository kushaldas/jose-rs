#!/usr/bin/env python3
"""Check ECDH key agreement (`ECDH-ES` and `ECDH-ES+A*KW`, RFC 7518 §4.6) against jwcrypto.

Pass the built ``jose-interop`` executable as the sole argument. Keys are made by
the Rust harness and imported into jwcrypto, so both sides work on the same JWK;
nothing is written to disk and no key material is printed.

What is checked, per curve and content algorithm:

1. **jose-rs emits, jwcrypto reads**, in both serializations. Direct key
   agreement conveys no key at all — the compact form's second segment is empty
   and the flattened form has no ``encrypted_key`` member — so this exercises
   jwcrypto's reading of the shape as well as its crypto.
2. **jwcrypto emits the compact form, jose-rs reads it.** That direction proves
   the two implementations really do agree on the agreed key: the ciphertext is
   jwcrypto's, and only a matching Concat KDF computation opens it.
3. **The JSON-serialization divergence.** jwcrypto ships ``epk`` in the
   *unprotected* ``header`` member (its compact form does put it in the protected
   header, where it has to go); jose-rs refuses a peer key it cannot
   authenticate (ADR 0013, ADR 0017), because ``epk`` decides which key the
   content is authenticated under. The refusal is asserted, with the compact
   round trip of the same key pair as the control: the rejection is about the
   member's location, not about jwcrypto's agreement.

panva (the Node ``jwe-ecdh`` matrix family) puts ``epk`` in the protected header
in both serializations and interoperates in both directions, so the divergence is
jwcrypto's and is one-directional.

The same three checks then run for the **key wrapping** modes
(``ECDH-ES+A128KW``/``+A192KW``/``+A256KW``), where the message additionally
carries the CEK wrapped under the agreed key. Those checks are what show the two
implementations agree on the Concat KDF's mode-dependent inputs — AlgorithmID the
ASCII ``alg`` rather than ``enc``, and ``keydatalen`` the KEK's length — since a
disagreement there is a tag failure, not a negotiation.
"""

import base64
import json
import subprocess
import sys

from jwcrypto import jwe, jwk

COMBOS = [
    ("P-256", "A128GCM"),
    ("P-256", "A128CBC-HS256"),
    ("P-384", "A192CBC-HS384"),
    ("P-521", "A256GCM"),
    ("P-521", "A256CBC-HS512"),
    # The OKP agreement curve (RFC 8037 §2): a different key type and a bare
    # u-coordinate, which is what makes these cells worth running rather than
    # redundant with the P-curves.
    ("X25519", "A256GCM"),
]

PLAINTEXT = b"direct ECDH key agreement interoperability"

FAILURES = []
PASSES = []


def check(name, condition, detail=""):
    if condition:
        PASSES.append(name)
    else:
        FAILURES.append(f"{name}: {detail}")


def _run(binary, argv, payload):
    return subprocess.run(
        [binary] + argv,
        input=json.dumps(payload).encode(),
        capture_output=True,
        timeout=60,
    )


KW_COMBOS = [
    ("ECDH-ES+A128KW", "P-256", "A256GCM"),
    ("ECDH-ES+A256KW", "X25519", "A256GCM"),
    ("ECDH-ES+A192KW", "P-384", "A128CBC-HS256"),
    ("ECDH-ES+A256KW", "P-521", "A128GCM"),
]

# A 256-bit CEK wrapped by a 128-bit agreed key: RFC 3394 adds one 64-bit
# integrity block, so the encrypted key is 40 octets. Length is asserted rather
# than eyeballed because it is what distinguishes "wrapped the CEK" from
# "wrapped the KEK" without trusting either implementation's own report.
KW_WRAPPED_LEN = {"A128GCM": 24, "A128CBC-HS256": 40, "A192CBC-HS384": 48, "A256GCM": 40}


def rust(binary, command, enc, payload, crv=None, alg="ECDH-ES"):
    argv = [command, "--alg", alg, "--enc", enc]
    if crv:
        argv += ["--crv", crv]
    result = _run(binary, argv, payload)
    if result.returncode != 0:
        raise AssertionError(f"{command} failed: {result.stderr.decode().strip()}")
    return json.loads(result.stdout)


def rust_stderr(binary, command, enc, payload, alg="ECDH-ES"):
    result = _run(binary, [command, "--alg", alg, "--enc", enc], payload)
    return "" if result.returncode == 0 else result.stderr.decode()


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def rust_to_jwcrypto(binary, crv, enc):
    """jose-rs produces, jwcrypto reads — flattened and compact."""
    label = f"jose-rs -> jwcrypto [{crv}/{enc}]"
    private = rust(binary, "gen-key", enc, {}, crv=crv)
    public = rust(binary, "export-pub", enc, private)
    recipient = jwk.JWK(**private)

    # The producer encrypts against the public half only.
    flattened = rust(
        binary,
        "encrypt-flattened",
        enc,
        {"jwk": public, "plaintext_b64u": b64u(PLAINTEXT)},
    )["jwe"]
    message = json.loads(flattened)
    check(f"{label}: no encrypted_key member", "encrypted_key" not in message, message)

    obj = jwe.JWE()
    try:
        obj.deserialize(flattened)
        obj.decrypt(recipient)
    except Exception as error:  # noqa: BLE001 - reported as a failed check
        check(f"{label}: flattened", False, f"jwcrypto refused it: {error}")
        return
    check(f"{label}: flattened plaintext", obj.payload == PLAINTEXT, obj.payload)

    header = json.loads(unb64u(message["protected"]))
    check(f"{label}: epk is in the protected header", "epk" in header, header)
    check(f"{label}: epk carries no private part", "d" not in header.get("epk", {}), header)
    check(f"{label}: epk names the recipient's curve", header.get("epk", {}).get("crv") == crv, header)

    compact = rust(
        binary,
        "encrypt-compact",
        enc,
        {"jwk": public, "plaintext_b64u": b64u(PLAINTEXT)},
    )["jwe"]
    check(
        f"{label}: compact conveys no encrypted key",
        compact.split(".")[1] == "",
        compact[:40],
    )
    obj = jwe.JWE()
    try:
        obj.deserialize(compact)
        obj.decrypt(recipient)
    except Exception as error:  # noqa: BLE001
        check(f"{label}: compact", False, f"jwcrypto refused it: {error}")
        return
    check(f"{label}: compact plaintext", obj.payload == PLAINTEXT, obj.payload)


def jwcrypto_to_rust(binary, crv, enc):
    """jwcrypto produces; jose-rs reads the compact form and refuses the JSON one."""
    label = f"jwcrypto -> jose-rs [{crv}/{enc}]"
    private = rust(binary, "gen-key", enc, {}, crv=crv)
    recipient = jwk.JWK(**private)

    def produce():
        token = jwe.JWE(plaintext=PLAINTEXT, protected={"alg": "ECDH-ES", "enc": enc})
        token.add_recipient(recipient)
        return token

    # Control first: jwcrypto's own agreement, compactly framed, must open. The
    # compact form has nowhere to put `epk` but the protected header, so this is
    # the same crypto as the JSON case with only the header placement differing.
    compact = produce().serialize(compact=True)
    protected = json.loads(unb64u(compact.split(".")[0]))
    check(
        f"{label}: jwcrypto compacts epk into the protected header",
        "epk" in protected,
        protected,
    )
    out = _run(binary, ["decrypt-compact", "--alg", "ECDH-ES", "--enc", enc],
               {"jwk": private, "jwe": compact})
    if out.returncode != 0:
        check(f"{label}: compact plaintext", False, out.stderr.decode())
    else:
        got = json.loads(out.stdout)
        check(
            f"{label}: compact plaintext",
            unb64u(got["plaintext_b64u"]) == PLAINTEXT,
            got,
        )
        check(
            f"{label}: reports the authenticated epk",
            got.get("protected_header", {}).get("epk", {}).get("crv") == crv,
            got,
        )

    # The divergence: jwcrypto's JSON form ships `epk` unprotected, and this
    # crate will not derive a key from a peer value the sender did not
    # integrity-protect.
    flattened = produce().serialize()
    message = json.loads(flattened)
    unprotected = message.get("header") or {}
    check(
        f"{label}: jwcrypto ships epk unprotected in JSON (documented divergence)",
        "epk" in unprotected and "epk" not in json.loads(unb64u(message["protected"])),
        message,
    )
    refused = rust_stderr(
        binary, "decrypt-flattened", enc, {"jwk": private, "jwe": flattened}
    )
    check(
        f"{label}: jose-rs refuses the unprotected epk by name",
        bool(refused) and "epk" in refused and "integrity protected" in refused,
        refused,
    )


def rust_to_jwcrypto_kw(binary, alg, crv, enc):
    """jose-rs emits a wrapped-key agreement message; jwcrypto reads both forms."""
    label = f"jose-rs -> jwcrypto [{alg} {crv}/{enc}]"
    private = rust(binary, "gen-key", enc, {}, crv=crv, alg=alg)
    public = rust(binary, "export-pub", enc, private)
    recipient = jwk.JWK(**private)

    flattened = rust(
        binary,
        "encrypt-flattened",
        enc,
        {"jwk": public, "plaintext_b64u": b64u(PLAINTEXT)},
        alg=alg,
    )["jwe"]
    message = json.loads(flattened)
    wrapped = unb64u(message.get("encrypted_key", ""))
    check(
        f"{label}: carries the CEK wrapped under the agreed key",
        len(wrapped) == KW_WRAPPED_LEN[enc],
        f"{len(wrapped)} octets, expected {KW_WRAPPED_LEN[enc]}",
    )
    obj = jwe.JWE()
    try:
        obj.deserialize(flattened)
        obj.decrypt(recipient)
    except Exception as error:  # noqa: BLE001
        check(f"{label}: flattened", False, f"jwcrypto refused it: {error}")
        return
    check(f"{label}: flattened plaintext", obj.payload == PLAINTEXT, obj.payload)

    compact = rust(
        binary,
        "encrypt-compact",
        enc,
        {"jwk": public, "plaintext_b64u": b64u(PLAINTEXT)},
        alg=alg,
    )["jwe"]
    check(
        f"{label}: compact conveys the wrapped key",
        compact.split(".")[1] != "",
        compact[:40],
    )
    obj = jwe.JWE()
    try:
        obj.deserialize(compact)
        obj.decrypt(recipient)
    except Exception as error:  # noqa: BLE001
        check(f"{label}: compact", False, f"jwcrypto refused it: {error}")
        return
    check(f"{label}: compact plaintext", obj.payload == PLAINTEXT, obj.payload)


def jwcrypto_to_rust_kw(binary, alg, crv, enc):
    """jwcrypto emits a wrapped-key agreement message; jose-rs reads the compact form."""
    label = f"jwcrypto -> jose-rs [{alg} {crv}/{enc}]"
    private = rust(binary, "gen-key", enc, {}, crv=crv, alg=alg)

    # A fresh object per serialization: reusing one JWE instance and serializing
    # it compactly first makes jwcrypto's later JSON output drop the `header`
    # member it had produced, which would test the library's object model rather
    # than its wire behaviour.
    def produce():
        token = jwe.JWE(plaintext=PLAINTEXT, protected={"alg": alg, "enc": enc})
        token.add_recipient(jwk.JWK(**private))
        return token

    compact = produce().serialize(compact=True)
    check(
        f"{label}: jwcrypto conveys the wrapped key",
        compact.split(".")[1] != "",
        compact[:40],
    )
    out = _run(
        binary,
        ["decrypt-compact", "--alg", alg, "--enc", enc],
        {"jwk": private, "jwe": compact},
    )
    if out.returncode != 0:
        check(f"{label}: compact plaintext", False, out.stderr.decode())
        return
    got = json.loads(out.stdout)
    check(
        f"{label}: compact plaintext",
        unb64u(got["plaintext_b64u"]) == PLAINTEXT,
        got,
    )
    check(
        f"{label}: reports the authenticated epk",
        got.get("protected_header", {}).get("epk", {}).get("crv") == crv,
        got,
    )

    # Same divergence as direct agreement, asserted for this mode too.
    flattened = produce().serialize()
    refused = rust_stderr(
        binary, "decrypt-flattened", enc, {"jwk": private, "jwe": flattened}, alg=alg
    )
    check(
        f"{label}: jose-rs refuses jwcrypto's unprotected epk by name",
        bool(refused) and "epk" in refused and "integrity protected" in refused,
        refused,
    )


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: jwe_ecdh_es_jwcrypto.py /path/to/jose-interop")
    binary = sys.argv[1]
    for crv, enc in COMBOS:
        rust_to_jwcrypto(binary, crv, enc)
        jwcrypto_to_rust(binary, crv, enc)
    for alg, crv, enc in KW_COMBOS:
        rust_to_jwcrypto_kw(binary, alg, crv, enc)
        jwcrypto_to_rust_kw(binary, alg, crv, enc)

    for line in PASSES:
        print(f"  ok   {line}")
    if FAILURES:
        for line in FAILURES:
            print(f"  FAIL {line}")
        print(f"\nECDH agreement / jwcrypto: {len(PASSES)} passed, {len(FAILURES)} failed")
        sys.exit(1)
    print(f"\nECDH agreement / jwcrypto: {len(PASSES)} passed, 0 failed")


if __name__ == "__main__":
    main()
