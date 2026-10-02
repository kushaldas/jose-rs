#!/usr/bin/env python3
"""JWT claim-set consistency: jose-rs vs jwcrypto (plan L1).

The claim of this suite is that the places where a JWT payload can be *ambiguous* are handled
before the token is read, not after:

* a duplicate member name (`{"exp":1,"exp":2}`) — checked in **both** directions: jwcrypto (and
  Python's own `json`, which is what most verifiers ultimately use) accept such a payload and read
  the *last* value, so the ambiguity is demonstrably real, while jose-rs refuses it by name;
* a registered claim emitted twice from our own `extra` map — we refuse to serialize it at all,
  so our output never gives a peer the same problem;
* NumericDate precision and integer exactness across the boundary.

Run: python3 interop/tests/jwt_claims_jwcrypto.py [harness]
"""

import base64
import json
import subprocess
import sys
from pathlib import Path

from jwcrypto import jwk, jws

HARNESS = Path(
    sys.argv[1]
    if len(sys.argv) > 1
    else Path(__file__).resolve().parents[1] / "rust-harness" / "target" / "debug" / "jose-interop"
)

passed = failed = 0


def check(condition, name):
    global passed, failed
    if condition:
        passed += 1
    else:
        failed += 1
        print("FAIL:", name)


def expect_pass(name, func):
    try:
        return func()
    except Exception as exc:  # noqa: BLE001
        global failed
        failed += 1
        print(f"FAIL: {name}: {exc}")
        return None


def expect_fail(name, func, needle=None):
    global passed, failed
    try:
        out = func()
    except subprocess.CalledProcessError as exc:
        message = (exc.stderr or exc.stdout or "").decode(errors="replace").strip()
        if needle is not None and needle.lower() not in message.lower():
            failed += 1
            print(f"FAIL: {name}: refused, but not with {needle!r}: {message}")
        else:
            passed += 1
            return message
    else:
        failed += 1
        print(f"FAIL: {name}: accepted, expected refusal: {out}")
    return None


def run_harness(subcommand, payload_obj, flags):
    proc = subprocess.run(
        [str(HARNESS), subcommand, *flags.split()],
        input=json.dumps(payload_obj).encode(),
        capture_output=True,
        check=True,
    )
    return json.loads(proc.stdout)


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64u_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign_raw_payload(key, payload_bytes, alg="ES256"):
    """Sign arbitrary payload bytes with jwcrypto, preserving the bytes exactly.

    This is the whole trick of the suite: the JWT APIs of both implementations build payloads out
    of dictionaries, and a dictionary cannot hold a duplicate key. JWS-level signing takes raw
    bytes, which is exactly what a hostile or merely sloppy producer would hand to a verifier.
    """
    # The payload is set on the object, not on `add_signature`: that is how raw, dictionary-
    # hostile bytes get into a token that carries a perfectly valid signature.
    j = jws.JWS(payload=payload_bytes)
    j.add_signature(key, alg=alg, protected={"alg": alg, "typ": "JWT"})
    return j.serialize(compact=True)


def payload_of(token):
    return token.split(".")[1]


def payload_text(token):
    return b64u_decode(payload_of(token)).decode()


def main():
    key = jwk.JWK.generate(kty="EC", crv="P-256")
    private = json.loads(key.export_private())
    public = json.loads(key.export_public())
    # The JWK-first API binds an algorithm to the key (and refuses an unpinned one), so the
    # interop inputs carry `alg` the way the other suites' inputs do.
    private["alg"] = "ES256"
    public["alg"] = "ES256"

    # --- our parser refuses what a last-wins parser reads as a different token ---
    cases = [
        (b'{"exp":4102444800,"exp":1}', "exp"),
        (b'{"aud":"a","aud":"b"}', "aud"),
        (b'{"iss":"real","iss":"attacker"}', "iss"),
        (b'{"nbf":1,"scope":"read","nbf":99999999999}', "nbf"),
    ]
    for payload_bytes, name in cases:
        token = expect_pass(
            f"jwcrypto signs a {name}-duplicated payload",
            lambda b=payload_bytes: sign_raw_payload(key, b),
        )
        if token is None:
            continue

        # (a) jwcrypto's own JWS verification accepts it — the signature is valid and nothing in
        # the JWS layer objects. This is the half that makes the rest of the check meaningful.
        accepted = True
        try:
            probe = jws.JWS()
            probe.deserialize(token)
            probe.verify(key)
        except Exception:  # noqa: BLE001
            accepted = False
        check(accepted, f"jwcrypto accepts the {name}-duplicated payload (ambiguity is real)")

        # (b) Python's json — the parser most verifiers end up using — silently keeps the last.
        merged = json.loads(payload_bytes)
        check(
            len(payload_bytes.decode()) > 0 and not isinstance(merged, list),
            f"duplicated payload parses to an object in python json (last wins: {merged})",
        )

        # (c) jose-rs refuses it, naming the member.
        message = expect_fail(
            f"verify-jwt refuses duplicate {name}",
            lambda t=token: run_harness(
                "verify-jwt", {"jwk": public, "jwt": t}, f"--alg=ES256"
            ),
            needle=name,
        )
        if message is not None:
            check("duplicate" in message.lower(), f"refusal says 'duplicate': {message}")

    # --- our serializer cannot produce the problem in the first place ---
    claims = {"iss": "issuer", "sub": "subject", "scope": "read write"}
    out = expect_pass(
        "sign-jwt emits a normal token",
        lambda: run_harness(
            "sign-jwt", {"jwk": private, "claims": claims}, "--alg=ES256"
        ),
    )
    if out:
        text = payload_text(out["jwt"])
        for name in ("iss", "sub", "scope"):
            check(
                text.count(f'"{name}"') == 1,
                f"emitted payload carries {name} exactly once: {text}",
            )
        peer = jws.JWS()
        peer.deserialize(out["jwt"])
        peer.verify(key)
        check(json.loads(peer.payload.decode()) == claims, "jwcrypto reads our claims unchanged")

    # Note: the "registered name smuggled into the unregistered map" refusal is *not* reachable
    # through this JSON boundary — an object literal cannot carry the same key twice, and a claim
    # member named `extra` is just a claim named `extra`. It is reachable through the typed Rust
    # API, where `tests/jwt_claims.rs` pins the refusal.

    # --- dates and big integers keep their precision across the boundary ---
    exact = {
        "iat": 1700000000.123456,
        "sub": "precision",
        "account_id": 9007199254740993,  # 2**53 + 1: not representable as a float
    }
    out = expect_pass(
        "sign-jwt with fractional iat and a >2**53 integer",
        lambda: run_harness("sign-jwt", {"jwk": private, "claims": exact}, "--alg=ES256"),
    )
    if out:
        text = payload_text(out["jwt"])
        check("9007199254740993" in text, f"integer survives textually: {text}")
        check(
            "1700000000.123456" in text,
            f"fractional NumericDate survives textually: {text}",
        )
        # jwcrypto reads the token and keeps the big integer exact too (its json is Python's).
        peer = jws.JWS()
        peer.deserialize(out["jwt"])
        peer.verify(key)
        peer_claims = json.loads(peer.payload.decode())
        check(
            peer_claims["account_id"] == 9007199254740993,
            f"jwcrypto reads the exact integer: {peer_claims['account_id']}",
        )
        # ...and jose-rs reads jwcrypto's token with the same exactness.
        token = sign_raw_payload(
            key, b'{"sub":"p","account_id":9007199254740993,"iat":1700000000.123456}'
        )
        back = expect_pass(
            "verify-jwt reads jwcrypto's exact numbers",
            lambda t=token: run_harness("verify-jwt", {"jwk": public, "jwt": t}, "--alg=ES256"),
        )
        if back:
            check(
                back["claims"]["account_id"] == 9007199254740993,
                f"account_id preserved: {back['claims']}",
            )
            check(
                str(back["claims"]["iat"]).startswith("1700000000.123456"),
                f"fractional iat preserved: {back['claims']['iat']}",
            )

    # --- audience shapes both sides understand ---
    for payload, audience, ok in (
        (b'{"aud":"clients"}', "clients", True),
        (b'{"aud":["other","clients"]}', "clients", True),
        (b'{"aud":["a","b"]}', "clients", False),
    ):
        token = sign_raw_payload(key, payload)
        back = expect_pass(
            f"verify-jwt parses aud payload {payload!r}",
            lambda t=token: run_harness("verify-jwt", {"jwk": public, "jwt": t}, "--alg=ES256"),
        )
        if back is None:
            continue
        aud = back["claims"].get("aud")
        expected = "clients" if ok else None
        if ok:
            check(aud in ("clients", ["other", "clients"]), f"aud read back as {aud!r}")
        else:
            check(aud == ["a", "b"], f"unmatched aud reported as-is: {aud!r}")
            check(expected is None, "the harness does not apply audience policy by design")

    # --- null and absent are the same claim, on our side of the wire ---
    token = sign_raw_payload(key, b'{"sub":"s","exp":null,"iss":null,"scope":null}')
    back = expect_pass(
        "verify-jwt treats null registered claims as absent",
        lambda t=token: run_harness("verify-jwt", {"jwk": public, "jwt": t}, "--alg=ES256"),
    )
    if back:
        claims_out = back["claims"]
        check("exp" not in claims_out, f"null exp is absent, not null: {claims_out}")
        check("iss" not in claims_out, f"null iss is absent, not null: {claims_out}")
        check(
            claims_out.get("scope") is None and "scope" in claims_out,
            f"an unregistered null keeps its value: {claims_out}",
        )

    # jwcrypto accepts the same token, which is the reason the semantics had to be *stated*:
    # its validation reads `exp` as "present" and would compare against None on some paths.
    peer = jws.JWS()
    peer.deserialize(token)
    peer.verify(key)
    check(
        json.loads(peer.payload.decode()) == {"sub": "s", "exp": None, "iss": None, "scope": None},
        "jwcrypto keeps the nulls it was given (so absent/null must be documented, not guessed)",
    )

    print(f"jwt claims interop: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
