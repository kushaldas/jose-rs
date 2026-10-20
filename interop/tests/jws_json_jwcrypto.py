#!/usr/bin/env python3
"""JWK-aware JSON JWS (flattened + general) against jwcrypto (plan L2).

The compact serialization has had peer coverage for a long time; the JSON serializations are
where a caller used to have to leave the JWK-aware API and hand-build signers. This suite drives
the JWK-aware JSON paths against jwcrypto and pins the one place the two implementations differ
*by policy rather than by wire format*: what "this document verifies" means when there are
several signatures.

Findings asserted here, because they are the reason the API takes an explicit policy:

* jwcrypto's `JWS.verify(key)` is **any-of** — a two-signature document where only the signature
  made by `key` is intact still verifies. jose-rs's `SignaturePolicy::Any` matches that, and
  `SignaturePolicy::All` is the stricter statement a caller can choose instead.
* jwcrypto's `JWKSet` selection does not handle per-signature `kid` values on a General JWS (it
  raises "No working key found in key set" even when the set holds both signing keys). Asserted
  rather than worked around: if a future jwcrypto fixes it, this check tells us.

Run: python3 interop/tests/jws_json_jwcrypto.py [harness]
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


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def make_ed(kid):
    key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
    key["alg"] = "EdDSA"
    key["kid"] = kid
    return key


def make_ec(kid, crv="P-256", alg="ES256"):
    key = jwk.JWK.generate(kty="EC", crv=crv)
    key["alg"] = alg
    key["kid"] = kid
    return key


def main():
    payload = b"shared payload under several signatures"

    ed = make_ed("ed-1")
    ec = make_ec("ec-1")
    ed_rust = json.loads(ed.export_private())
    ec_rust = json.loads(ec.export_private())

    # --- Rust emits a General JWS; jwcrypto reads every signature ---
    general = run(
        "sign-general-jwk",
        {
            "entries": [
                {"jwk": ed_rust, "alg": "EdDSA", "header": {"kid": "ed-1"}},
                {"jwk": ec_rust, "alg": "ES256", "header": {"kid": "ec-1"}},
            ],
            "payload_b64u": b64u(payload),
        },
    )["jws"]
    check(len(general["signatures"]) == 2, "general JWS carries two signatures")
    check(
        general["payload"] == b64u(payload),
        "payload member is the base64url payload",
    )

    peer = jws.JWS()
    peer.deserialize(json.dumps(general))
    for name, key in (("EdDSA key", ed), ("EC key", ec)):
        accepted = True
        try:
            peer.verify(key)
        except Exception as exc:  # noqa: BLE001
            accepted = False
            print("   peer said:", exc)
        check(accepted, f"jwcrypto verifies our general JWS with its {name}")
    check(
        peer.payload.decode() == payload.decode(),
        "jwcrypto reads the payload bytes unchanged",
    )
    protected_algs = [
        json.loads(entry["protected"]) for entry in peer.objects["signatures"]
    ]
    check(
        [p.get("kid") for p in protected_algs] == ["ed-1", "ec-1"],
        "per-signature protected headers survive the peer's parser",
    )
    check(
        [p.get("alg") for p in protected_algs] == ["EdDSA", "ES256"],
        "per-signature algorithms are what we signed with",
    )

    # Peer behaviour we do not emulate but must notice changing.
    set_verify_failed = False
    try:
        peer.verify(jwk.JWKSet(from_list=[ed, ec]))
    except Exception:  # noqa: BLE001
        set_verify_failed = True
    check(
        set_verify_failed,
        "jwcrypto JWKSet selection still cannot drive a multi-kid General JWS "
        "(if this starts passing, re-read its semantics before trusting a set here)",
    )

    # --- jwcrypto emits a General JWS; we read it, under both policies ---
    token = jws.JWS(payload=payload)
    token.add_signature(ed, protected={"alg": "EdDSA", "kid": "ed-1"})
    token.add_signature(ec, protected={"alg": "ES256", "kid": "ec-1"})
    jwcrypto_general = json.loads(token.serialize(compact=False))

    for policy in ("any", "all"):
        out = run(
            "verify-general-jwk",
            {
                "jwks": [json.loads(ed.export_public()), json.loads(ec.export_public())],
                "jws": jwcrypto_general,
                "policy": policy,
            },
        )
        check(
            unb64(out["payload_b64u"]) == payload,
            f"verify-general-jwk({policy}) reads jwcrypto's document",
        )
        if policy == "all":
            check(
                [r["verified"] for r in out["results"]] == [True, True],
                f"policy=all reports both signatures verified: {out['results']}",
            )
            check(
                [r["key_index"] for r in out["results"]] == [0, 1],
                "the report says which key signed which signature",
            )
        else:
            # `any` short-circuits, and the report says so: an entry it never touched is
            # `attempted: false`, not a false verdict about the document.
            check(
                out["results"][0]["verified"],
                "policy=any verified the first signature and stopped",
            )
            second = out["results"][1]
            check(
                not second["attempted"]
                and "already satisfied" in (second["error"] or ""),
                f"policy=any is honest about what it skipped: {second}",
            )

    # --- partial corruption: the policy is the only difference ---
    broken = json.loads(json.dumps(jwcrypto_general))
    broken["signatures"][1]["signature"] = "AAAA" + broken["signatures"][1]["signature"][4:]

    peer_any_of = True
    try:
        peer2 = jws.JWS()
        peer2.deserialize(json.dumps(broken))
        peer2.verify(ed)
    except Exception:  # noqa: BLE001
        peer_any_of = False
    check(
        peer_any_of,
        "jwcrypto accepts the partly-broken document when *a* signature verifies (any-of)",
    )

    any_out = run(
        "verify-general-jwk",
        {
            "jwks": [json.loads(ed.export_public()), json.loads(ec.export_public())],
            "jws": broken,
            "policy": "any",
        },
    )
    check(
        unb64(any_out["payload_b64u"]) == payload,
        "policy=any accepts it too, matching the peer",
    )
    check(
        [r["verified"] for r in any_out["results"]] == [True, False],
        f"per-signature truth is reported: {any_out['results']}",
    )
    expect_fail(
        "policy=all refuses the same document",
        lambda: run(
            "verify-general-jwk",
            {
                "jwks": [json.loads(ed.export_public()), json.loads(ec.export_public())],
                "jws": broken,
                "policy": "all",
            },
        ),
        needle="all-signatures",
    )

    # --- no fall-through to an unrelated key ---
    expect_fail(
        "verify-general-jwk with only an unrelated key refuses",
        lambda: run(
            "verify-general-jwk",
            {"jwks": [json.loads(make_ed("unrelated").export_public())], "jws": jwcrypto_general},
        ),
        needle="no candidate key",
    )

    # --- flattened: unprotected per-signature header, detached, and plain ---
    unprotected = {"etsiU": {"commitmentType": "http://uri.etsi.org/19423/v1.2.3#signer"}}
    flat = run(
        "sign-flattened-jwk",
        {
            "jwk": ec_rust,
            "payload_b64u": b64u(payload),
            "header": {"kid": "ec-1"},
            "unprotected": unprotected,
        },
        ("--alg=ES256",),
    )["jws"]
    check(flat["header"] == unprotected, "unprotected header emitted as given")
    peer_flat = jws.JWS()
    peer_flat.deserialize(json.dumps(flat))
    peer_flat.verify(ec)
    check(peer_flat.payload.decode() == payload.decode(), "jwcrypto verifies our flattened JWS")
    # jwcrypto does not surface the per-signature unprotected header on its own object model, so
    # the peer-side claim here is the one that matters: it verified the document *we* emitted with
    # that member present. Byte-level fidelity of the member is asserted on the emitted JSON above.
    check(
        json.loads(json.dumps(flat))["header"] == unprotected,
        "the unprotected member we emitted is still there for a peer to read",
    )

    # jwcrypto -> us, with its own unprotected header.
    peer_out = jws.JWS(payload=payload)
    peer_out.add_signature(
        ec, protected={"alg": "ES256", "kid": "ec-1"}, header={"comment": "jwcrypto side"}
    )
    peer_flat_json = json.loads(peer_out.serialize(compact=False))
    back = run(
        "verify-flattened-jwk",
        {"jwk": json.loads(ec.export_public()), "jws": peer_flat_json},
    )
    check(unb64(back["payload_b64u"]) == payload, "we verify jwcrypto's flattened JWS")

    # --- detached payloads in both directions ---
    detached = run(
        "sign-flattened-jwk",
        {"jwk": ec_rust, "payload_b64u": b64u(payload), "detach": True},
        ("--alg=ES256",),
    )["jws"]
    check("payload" not in detached or detached["payload"] is None, "detached carries no payload")
    peer_det = jws.JWS()
    peer_det.deserialize(json.dumps(detached))
    peer_det.verify(ec, detached_payload=payload)
    check(True, "jwcrypto verifies our detached JWS")
    back = run(
        "verify-flattened-jwk",
        {
            "jwk": json.loads(ec.export_public()),
            "jws": detached,
            "detached_payload_b64u": b64u(payload),
        },
    )
    check(unb64(back["payload_b64u"]) == payload, "we verify our detached JWS out-of-band")

    # jwcrypto 1.6.1 cannot *emit* a detached JSON JWS (neither add_signature nor serialize
    # takes a detach flag), so there is no peer-side detached document to import. Asserted as a
    # peer limitation: if a future version grows the capability, this check fires and the
    # direction should be added rather than the claim quietly dropped.
    peer_can_detach = False
    try:
        probe = jws.JWS(payload=payload)
        probe.add_signature(ec, protected={"alg": "ES256"})
        probe.serialize(compact=False, detach_content=True)
        peer_can_detach = True
    except TypeError:
        peer_can_detach = False
    check(
        not peer_can_detach,
        "jwcrypto cannot emit a detached JSON JWS (peer limitation; re-check on upgrade)",
    )

    # The wrong out-of-band payload must not verify our detached document.
    expect_fail(
        "detached verification with the wrong out-of-band payload refuses",
        lambda: run(
            "verify-flattened-jwk",
            {
                "jwk": json.loads(ec.export_public()),
                "jws": detached,
                "detached_payload_b64u": b64u(b"wrong payload"),
            },
        ),
    )

    # --- a use:enc key is refused on the JSON path exactly as on the compact path ---
    # jwcrypto refuses to *sign* with a `use: enc` key (its own constraint check), so the token is
    # signed with a clean key and the same key material is then handed to *our* verifier marked
    # `use: enc`. That is the realistic misconfiguration: the document is fine, the local key
    # metadata says it must not be used for signatures.
    enc_dict = json.loads(ec.export_public())
    enc_dict["use"] = "enc"
    peer_sig = jws.JWS(payload=payload)
    peer_sig.add_signature(ec, protected={"alg": "ES256"})
    enc_token = json.loads(peer_sig.serialize(compact=False))
    expect_fail(
        "a use:enc key is refused rather than quietly used",
        lambda: run("verify-flattened-jwk", {"jwk": enc_dict, "jws": enc_token}),
        needle="use",
    )
    # ...and the same key without the constraint verifies it, proving the refusal was the metadata.
    ok = run(
        "verify-flattened-jwk",
        {"jwk": json.loads(ec.export_public()), "jws": enc_token},
    )
    check(unb64(ok["payload_b64u"]) == payload, "the same key without use:enc verifies it")

    print(f"jws json interop: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
