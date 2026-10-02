"""Check the JWE flattened JSON Serialization (RFC 7516 §7.2.2) against jwcrypto 1.6.1.

Pass the built jose-interop executable as the sole argument. Keys are generated
by the Rust harness and imported into jwcrypto, so the same JWK object is used
on both sides; nothing is written to disk and no private key material is
printed.

Three things are checked per (alg, enc) combination:

1. jose-rs emits a flattened JSON object and jwcrypto reads it (member names,
   base64url encodings, and the ``encrypted_key`` presence rule for ``dir``).
2. jwcrypto emits a flattened JSON object and jose-rs reads it;
2b. the same pair with **external additional authenticated data** (RFC 7516
   §7.2.1) in play, including the requirement that jose-rs refuses the message
   when the out-of-band bytes are withheld.
3. the shape jwcrypto produces by default — ``alg``/``kid`` in the
   per-recipient unprotected ``header`` member, as RFC 7516 §A.5 does — is read
   *and* policed: a key that pins the algorithm accepts it, a message whose
   unauthenticated ``alg`` has been tampered with is refused
   (docs/adr/0013).
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

# Out-of-band bytes for the external-AAD checks. jwcrypto and jose-rs both
# base64url-encode them into the `aad` member, so identical text here proves the
# two implementations agree on the content AAD input, not just the member name.
EXTERNAL_AAD = b"tenant=acme;purpose=interop"

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


def check_external_aad_both_directions(binary: str, alg: str, enc: str) -> None:
    """External AAD must be emitted, understood, and *required* by both sides."""
    key = rust(binary, "gen-key", alg, enc, {})
    aad_b64u = b64u(EXTERNAL_AAD)

    # jose-rs -> jwcrypto
    produced = rust(binary, "encrypt-flattened", alg, enc, {
        "jwk": key,
        "plaintext_b64u": b64u(PLAINTEXT),
        "aad_b64u": aad_b64u,
    })
    message = json.loads(produced["jwe"])
    assert message.get("aad") == aad_b64u, (
        "the aad member must carry the base64url octets verbatim: " + str(sorted(message))
    )
    token = jwe.JWE()
    token.deserialize(produced["jwe"], key=jwk.JWK(**key))
    assert token.payload == PLAINTEXT, "jwcrypto could not read a jose-rs external-AAD message"

    # jwcrypto -> jose-rs
    py_token = jwe.JWE(
        PLAINTEXT,
        protected=json.dumps({"alg": alg, "enc": enc}),
        recipient=jwk.JWK(**key),
        aad=EXTERNAL_AAD.decode(),
    )
    serialized = py_token.serialize()
    assert json.loads(serialized).get("aad") == aad_b64u, (
        "jwcrypto and jose-rs disagree on the aad member encoding"
    )
    decrypted = rust(binary, "decrypt-flattened", alg, enc, {
        "jwk": key,
        "jwe": serialized,
        "aad_b64u": aad_b64u,
    })
    assert base64.urlsafe_b64decode(decrypted["plaintext_b64u"] + "==") == PLAINTEXT

    # Withholding the out-of-band bytes must be refused, not silently accepted.
    stderr = rust_expect_failure(binary, "decrypt-flattened", alg, enc, {
        "jwk": key,
        "jwe": serialized,
    })
    assert "external additional authenticated data" in stderr, stderr

    # Wrong bytes must be refused too, by name.
    stderr = rust_expect_failure(binary, "decrypt-flattened", alg, enc, {
        "jwk": key,
        "jwe": serialized,
        "aad_b64u": b64u(b"tenant=evil;purpose=interop"),
    })
    assert "does not match" in stderr, stderr


def check_unprotected_alg_shape(binary: str, alg: str, enc: str) -> None:
    """jwcrypto's default output puts `alg`/`kid` in the unprotected `header`.

    RFC 7516 §7.2.1 permits that placement, and RFC 7516 §A.5 uses it, but the
    value is then attacker-controlled. jose-rs accepts it only for a key that
    pins the same algorithm (ADR 0013), so the header value is checked against
    the key instead of believed. Both halves of that rule are asserted here:
    the honest message decrypts, and a tampered `alg` is refused.
    """
    key = rust(binary, "gen-key", alg, enc, {})

    # jwcrypto's default puts *everything* unprotected, `enc` included, and
    # emits no protected member at all. jose-rs refuses that: an
    # unauthenticated `enc` decides how the ciphertext and tag octets are split,
    # which is a genuine substitution attack rather than a trust question. The
    # refusal is asserted so the boundary is never moved by accident.
    default_shape = jwe.JWE(
        PLAINTEXT,
        recipient=jwk.JWK(**key),
        header={"alg": alg, "enc": enc, **EXTRA_HEADER},
    ).serialize()
    assert "protected" not in json.loads(default_shape)
    stderr = rust_expect_failure(binary, "decrypt-flattened", alg, enc, {
        "jwk": key,
        "jwe": default_shape,
    })
    assert "\"protected\" is required" in stderr and "integrity protected" in stderr, stderr

    # The RFC 7516 §A.5 shape — `enc` protected, `alg`/`kid` unprotected — is
    # read, because the key pins the one value the message cannot prove.
    honest = jwe.JWE(
        PLAINTEXT,
        protected=json.dumps({"enc": enc}),
        recipient=jwk.JWK(**key),
        header={"alg": alg, **EXTRA_HEADER},
    ).serialize()
    decrypted = rust(binary, "decrypt-flattened", alg, enc, {
        "jwk": key,
        "jwe": honest,
    })
    assert base64.urlsafe_b64decode(decrypted["plaintext_b64u"] + "==") == PLAINTEXT, (
        "a pinned key must be able to read the RFC §A.5 shape"
    )
    reported = decrypted["unprotected_header"]
    assert reported.get("kid") == "interop-kid-1", reported
    assert reported.get("tenant") == "interop", reported

    # Tamper with the *unauthenticated* algorithm and the key's pin refuses it.
    # Rewrite the *unauthenticated* algorithm and ask for the rewritten one, so
    # the driver's own wiring check stays out of the way and what is being
    # tested is jose-rs's key pin: the key still says `alg`, the token now says
    # something else.
    tampered_alg = "A256KW" if alg != "A256KW" else "A128KW"
    tampered = json.loads(honest)
    tampered["header"]["alg"] = tampered_alg
    stderr = rust_expect_failure(binary, "decrypt-flattened", tampered_alg, enc, {
        "jwk": key,
        "jwe": json.dumps(tampered),
    })
    assert "does not match token header alg" in stderr, stderr

    # The RFC 7516 §A.5 three-location shape (enc protected, alg per-recipient
    # unprotected, jku shared unprotected) is read as well.
    three = jwe.JWE(
        PLAINTEXT,
        protected=json.dumps({"enc": enc}),
        unprotected={"jku": "https://interop.invalid/keys.jwks"},
        recipient=jwk.JWK(**key),
        header={"alg": alg, "kid": "interop-kid-1"},
    )
    decrypted = rust(binary, "decrypt-flattened", alg, enc, {
        "jwk": key,
        "jwe": three.serialize(),
    })
    assert base64.urlsafe_b64decode(decrypted["plaintext_b64u"] + "==") == PLAINTEXT
    reported = decrypted["unprotected_header"]
    assert reported.get("jku") == "https://interop.invalid/keys.jwks", reported
    assert reported.get("alg") == alg, reported


def main(binary: str) -> None:
    """Verify each producer using the other implementation."""
    for alg, enc in COMBOS:
        check_rust_to_jwcrypto(binary, alg, enc)
        check_jwcrypto_to_rust(binary, alg, enc)
        check_external_aad_both_directions(binary, alg, enc)
        check_unprotected_alg_shape(binary, alg, enc)
    print(json.dumps({
        "cell": "jwe-json-jwcrypto",
        "result": "PASS",
        "combos": len(COMBOS),
    }))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: jwe_json_jwcrypto.py <path/to/jose-interop>")
    main(sys.argv[1])
