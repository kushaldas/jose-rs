"""Check the JWE flattened JSON Serialization (RFC 7516 §7.2.2) against jwcrypto 1.6.1.

Pass the built jose-interop executable as the sole argument. Keys are generated
by the Rust harness and imported into jwcrypto, so the same JWK object is used
on both sides; nothing is written to disk and no private key material is
printed.

Three things are checked per (alg, enc) combination:

1. jose-rs emits a flattened JSON object and jwcrypto reads it (member names,
   base64url encodings, and the ``encrypted_key`` presence rule for ``dir``).
2. jwcrypto emits a flattened JSON object and jose-rs reads it.
3. jose-rs *refuses* the shape jwcrypto produces by default — ``alg``/``enc`` in
   the per-recipient unprotected ``header`` member. RFC 7516 §7.2.1 permits that
   shape and RFC 7516 §A.5 uses it; jose-rs requires the protected header until
   unprotected headers are implemented (docs/adr/0012). This is a documented
   divergence, asserted rather than discovered by accident.
"""

import base64
import json
import subprocess
import sys

from jwcrypto import jwk, jwe

# (key-management alg, content encryption enc) pairs both sides implement.
COMBOS = [
    ("dir", "A128GCM"),
    ("dir", "A256GCM"),
    ("dir", "A128CBC-HS256"),
    ("A128KW", "A128GCM"),
    ("A128KW", "A128CBC-HS256"),
    ("A192KW", "A192GCM"),
    ("A192KW", "A192CBC-HS384"),
    ("A256KW", "A256GCM"),
    ("A256KW", "A256CBC-HS512"),
]

# Extra protected-header members: one registered, one private. Both sides must
# report them back unchanged.
EXTRA_HEADER = {"kid": "interop-kid-1", "tenant": "interop"}

PLAINTEXT = b"JWE JSON serialization interoperability"


def rust(binary: str, command: str, algorithm: str, enc: str, value: dict) -> dict:
    """Call the Rust harness through its JSON stdin/stdout protocol."""
    result = subprocess.run(
        [binary, command, "--alg", algorithm, "--enc", enc],
        input=json.dumps(value),
        text=True,
        capture_output=True,
        check=True,
        timeout=60,
    )
    return json.loads(result.stdout)


def rust_expect_failure(binary: str, command: str, algorithm: str, enc: str, value: dict) -> str:
    """Run a Rust harness command that must fail, returning its stderr text."""
    result = subprocess.run(
        [binary, command, "--alg", algorithm, "--enc", enc],
        input=json.dumps(value),
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert result.returncode != 0, (
        f"{command} unexpectedly succeeded for {algorithm}/{enc}"
    )
    return (result.stderr or "").strip() or result.stdout


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def check_rust_to_jwcrypto(binary: str, alg: str, enc: str) -> None:
    """jose-rs produces the flattened JSON object; jwcrypto must read it."""
    key = rust(binary, "gen-key", alg, enc, {})
    produced = rust(binary, "encrypt-flattened", alg, enc, {
        "jwk": key,
        "plaintext_b64u": b64u(PLAINTEXT),
        "header": EXTRA_HEADER,
    })
    message = json.loads(produced["jwe"])

    # Serialization shape (RFC 7516 §7.2.1 presence rules).
    assert isinstance(message.get("protected"), str), message.keys()
    assert isinstance(message.get("ciphertext"), str), message.keys()
    assert isinstance(message.get("iv"), str), message.keys()
    assert isinstance(message.get("tag"), str), message.keys()
    assert "unprotected" not in message and "header" not in message, message.keys()
    assert "recipients" not in message and "aad" not in message, message.keys()
    if alg == "dir":
        assert "encrypted_key" not in message, (
            "RFC 7516 §7.2.1: encrypted_key must be absent when empty"
        )
    else:
        assert isinstance(message.get("encrypted_key"), str), message.keys()

    token = jwe.JWE()
    # jwcrypto's deserialize() takes the serialized text, not a parsed dict.
    token.deserialize(produced["jwe"], key=jwk.JWK(**key))
    assert token.payload == PLAINTEXT, "plaintext mismatch"
    # `jose_header` is jwcrypto's parsed view of the protected header.
    header = token.jose_header
    for name, want in EXTRA_HEADER.items():
        assert header.get(name) == want, f"{name}: {header}"
    assert header["alg"] == alg and header["enc"] == enc, header


def check_jwcrypto_to_rust(binary: str, alg: str, enc: str) -> None:
    """jwcrypto produces the flattened JSON object; jose-rs must read it."""
    key = rust(binary, "gen-key", alg, enc, {})
    protected = {"alg": alg, "enc": enc, **EXTRA_HEADER}
    token = jwe.JWE(
        PLAINTEXT,
        protected=json.dumps(protected),
        recipient=jwk.JWK(**key),
    )
    message = json.loads(token.serialize())
    assert "protected" in message, f"jwcrypto did not emit a protected member: {message.keys()}"

    decrypted = rust(binary, "decrypt-flattened", alg, enc, {
        "jwk": key,
        "jwe": json.dumps(message),
    })
    assert decrypted["ok"] is True
    assert base64.urlsafe_b64decode(decrypted["plaintext_b64u"] + "==") == PLAINTEXT
    header = decrypted["protected_header"]
    for name, want in EXTRA_HEADER.items():
        assert header.get(name) == want, f"{name}: {header}"


def check_unprotected_header_is_refused(binary: str, alg: str, enc: str) -> None:
    """jwcrypto's default output puts alg/enc in the unprotected `header`.

    jose-rs must refuse it by name (ADR 0012) instead of reading an
    unauthenticated `alg`. The assertion pins the *reason*, so a future change
    that silently starts accepting this shape has to update this test.
    """
    key = rust(binary, "gen-key", alg, enc, {})
    token = jwe.JWE(
        PLAINTEXT,
        recipient=jwk.JWK(**key),
        header={"alg": alg, "enc": enc, **EXTRA_HEADER},
    )
    message = json.loads(token.serialize())
    assert "header" in message and "protected" not in message, message.keys()

    stderr = rust_expect_failure(binary, "decrypt-flattened", alg, enc, {
        "jwk": key,
        "jwe": json.dumps(message),
    })
    assert "unsupported JWE JSON member" in stderr and "header" in stderr, stderr


def main(binary: str) -> None:
    """Verify each producer using the other implementation."""
    for alg, enc in COMBOS:
        check_rust_to_jwcrypto(binary, alg, enc)
        check_jwcrypto_to_rust(binary, alg, enc)
        check_unprotected_header_is_refused(binary, alg, enc)
    print(json.dumps({
        "cell": "jwe-json-jwcrypto",
        "result": "PASS",
        "combos": len(COMBOS),
    }))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: jwe_json_jwcrypto.py <path/to/jose-interop>")
    main(sys.argv[1])
