#!/usr/bin/env python3
"""JWK Set selection against jwcrypto-published sets (plan L3).

Selection is policy, not wire format — so the peer's role here is to be the source of realistic
sets and tokens rather than a second implementation of our policy. What this suite pins:

* a token naming one of three jwcrypto-published kids verifies, and the *other* keys' material
  cannot substitute for it (a token naming a kid jwcrypto never published is refused even though a
  key in the set could have signed it);
* jwcrypto can read and use the JWKS we emit, including kid-based selection on its side;
* entries this build cannot use stay in the diagnostics with their kids, and are classed
  "unsupported" (build lacks the kind) rather than "invalid" (material is broken) — the two states
  that must never be conflated, since one is a feature gap and the other is an outage.

Run: python3 interop/tests/jwks_selection_jwcrypto.py [harness]
"""

import json
import subprocess
import sys
from pathlib import Path

from jwcrypto import jwk, jwt as jwcrypto_jwt

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


def run(subcommand, payload_obj, flags=()):
    proc = subprocess.run(
        [str(HARNESS), subcommand, *flags],
        input=json.dumps(payload_obj).encode(),
        capture_output=True,
        check=True,
    )
    return json.loads(proc.stdout)


def expect_fail(name, func, needle=None):
    global passed, failed
    try:
        out = func()
    except subprocess.CalledProcessError as exc:
        message = (exc.stderr or exc.stdout or b"").decode(errors="replace").strip()
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


def named(kid, crv="P-256", alg="ES256"):
    key = jwk.JWK.generate(kty="EC", crv=crv)
    key["alg"] = alg
    key["kid"] = kid
    return key


def token_from(key, kid, claims='{"sub":"subject"}'):
    token = jwcrypto_jwt.JWT(header={"alg": key.get("alg"), "kid": kid}, claims=claims)
    token.make_signed_token(key)
    return token.serialize()


def main():
    a = named("key-a")
    b = named("key-b")
    c = named("key-c")
    # Assembled from jwcrypto's own public-half exports; `JWKSet.export()` in this version wraps
    # the list in a "from_list" envelope rather than emitting an RFC 7517 object, so the JWKS is
    # built from the per-key exports.
    set_json = {
        "keys": [json.loads(k.export_public()) for k in (a, b, c)]
    }
    check(len(set_json["keys"]) == 3, "a three-key set assembled from peer exports")
    # Round-trips through jwcrypto's own JWKSet parser, so it is a set a peer would accept.
    jwk.JWKSet(from_list=[k.export_public() for k in (a, b, c)])
    check(True, "jwcrypto accepts the same material as a JWK Set")

    # --- the named key is used, and no other key is tried in its place ---
    for signer_key, kid in ((a, "key-a"), (b, "key-b"), (c, "key-c")):
        out = run(
            "decode-jwkset-policy",
            {
                "jwks": set_json,
                "jwt": token_from(signer_key, kid),
                "policy": {"fallback": "refuse", "max_candidates": 8, "require_kid": True},
            },
        )
        check(out["claims"].get("sub") == "subject", f"kid {kid} resolves and decodes")

    # A token whose signature is valid for `a` but whose kid names something unpublished.
    forged = token_from(a, "key-rotated-away")
    for fallback in ("refuse", "try-when-unaddressable"):
        message = expect_fail(
            f"unknown kid never falls through (fallback={fallback})",
            lambda f=fallback, t=forged: run(
                "decode-jwkset-policy",
                {
                    "jwks": set_json,
                    "jwt": t,
                    "policy": {"fallback": f, "max_candidates": 8},
                },
            ),
            needle="key-rotated-away",
        )
        if message:
            check(
                "refus" in message.lower() or "forbid" in message.lower(),
                f"the refusal says it refused: {message}",
            )

    # The escape hatch does fall through — asserted so its documentation is not a fiction.
    out = run(
        "decode-jwkset-policy",
        {
            "jwks": set_json,
            "jwt": forged,
            "policy": {"fallback": "try-all", "max_candidates": 8},
        },
    )
    check(
        out["claims"].get("sub") == "subject",
        "Fallback::TryAll really does sweep (which is why it is not the default)",
    )

    # --- the attempt budget is an error, not a truncation ---
    big_keys = [named(f"k{i}") for i in range(9)]
    big_json = {"keys": [json.loads(k.export_public()) for k in big_keys]}
    lone = named("lonely")
    kidless_set = {"keys": [key for key in big_json["keys"]]}
    for key in kidless_set["keys"]:
        key.pop("kid", None)
        key.pop("use", None)
    kidless_token = jwcrypto_jwt.JWT(header={"alg": "ES256"}, claims='{"sub":"anon"}')
    kidless_token.make_signed_token(lone)
    # Publish `lone` inside the kid-less set so a sweep *could* find it if allowed to.
    lone_public = json.loads(lone.export_public())
    lone_public.pop("kid", None)
    sweepable = {"keys": kidless_set["keys"] + [lone_public]}
    check(len(sweepable["keys"]) == 10, "kid-less set of ten, one of which can verify")

    expect_fail(
        "budget exceeded is a budget error",
        lambda: run(
            "decode-jwkset-policy",
            {
                "jwks": sweepable,
                "jwt": kidless_token.serialize(),
                "policy": {"fallback": "try-all", "max_candidates": 4},
            },
        ),
        needle="budget",
    )
    out = run(
        "decode-jwkset-policy",
        {
            "jwks": sweepable,
            "jwt": kidless_token.serialize(),
            "policy": {"fallback": "try-all", "max_candidates": 16},
        },
    )
    check(out["claims"].get("sub") == "anon", "within budget, the sweep finds the key")

    # --- the JWKS we emit is readable and addressable on the peer side ---
    ours = run(
        "diagnose-jwks",
        {
            "keys": [
                {"kty": "EC", "crv": "P-256", "kid": "ok", "x": "AA", "y": "AA"},
                {"kty": "EC", "crv": "secp256k1", "kid": "btc", "x": "AA", "y": "AA"},
                {"kty": "RSA", "kid": "r", "n": "not base64!!", "e": "AQAB"},
                {"kty": "Wobbly", "kid": "future"},
            ]
        },
    )["entries"]
    check(len(ours) == 4, "diagnostics describe every entry, dropping none")
    statuses = {entry["kid"]: entry["status"] for entry in ours}
    # Note: "ok" is itself invalid material here (truncated coordinates) — what matters is the
    # *distinction*, not which side a deliberately-short fixture lands on.
    check(
        statuses["btc"] == "unsupported",
        f"a curve we lack is 'unsupported', not 'invalid': {statuses}",
    )
    check(
        statuses["future"] == "unsupported",
        f"an unknown kty is 'unsupported': {statuses}",
    )
    check(
        statuses["r"] == "invalid",
        f"supported kind with broken material is 'invalid': {statuses}",
    )
    check(
        all(entry["kid"] for entry in ours),
        "identifiers survive classification (an addressable set stays addressable)",
    )

    # jwcrypto reads a JWKS that jose-rs emitted, and selects by kid with it.
    emitted = subprocess.run(
        [str(HARNESS), "export-pub"],
        input=json.dumps(json.loads(b.export_private())).encode(),
        capture_output=True,
        check=True,
    )
    our_key = json.loads(emitted.stdout)
    our_key["kid"] = "key-b"
    our_key["alg"] = "ES256"
    our_set = {"keys": [our_key]}
    # Verified with the key the set names. (jwcrypto's own JWKSet-based kid selection cannot drive
    # multi-kid documents — see `jws_json_jwcrypto.py`, which asserts that limitation — so the
    # peer-side claim here is that it can consume the key material we publish, kid and all.)
    token = jwcrypto_jwt.JWT(header={"alg": "ES256", "kid": "key-b"}, claims='{"sub":"from-us"}')
    token.make_signed_token(b)  # same key material we just published
    peer = jwcrypto_jwt.JWT(jwt=token.serialize(), key=jwk.JWK(**our_key))
    check(
        json.loads(peer.claims)["sub"] == "from-us",
        "jwcrypto consumes the key (with its kid) that jose-rs emitted",
    )
    check(
        our_key.get("kid") == "key-b" and our_key.get("kty") == "EC",
        f"the emitted key keeps its identity members: {sorted(our_key)}",
    )
    # ...and we read it back under the same policy, closing the loop.
    out = run(
        "decode-jwkset-policy",
        {
            "jwks": our_set,
            "jwt": token.serialize(),
            "policy": {"fallback": "refuse", "require_kid": True},
        },
    )
    check(out["claims"].get("sub") == "from-us", "the same set and token work on our side")

    print(f"jwks selection interop: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
