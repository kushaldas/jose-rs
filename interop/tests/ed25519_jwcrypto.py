"""Check Ed25519 and legacy EdDSA compact interoperability with jwcrypto 1.6.1.

Pass the built jose-interop executable as the sole argument. Generates disposable
keys in memory and never writes or prints private key material.
"""

import base64
import json
import subprocess
import sys

from jwcrypto import jwk, jws


def rust(binary: str, command: str, algorithm: str, value: dict) -> dict:
    """Call the Rust harness through its JSON stdin/stdout protocol."""
    result = subprocess.run(
        [binary, command, "--alg", algorithm],
        input=json.dumps(value),
        text=True,
        capture_output=True,
        check=True,
        timeout=30,
    )
    return json.loads(result.stdout)


def main(binary: str) -> None:
    """Verify each producer using the other implementation and public keys."""
    payload = b"Ed25519 interoperability"
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    for algorithm in ("Ed25519", "EdDSA"):
        rust_key = rust(binary, "gen-key", algorithm, {})
        signed = rust(binary, "sign-compact", algorithm, {
            "jwk": rust_key, "payload_b64u": encoded,
        })
        public = jwk.JWK(**rust_key).public()
        verified = jws.JWS()
        verified.deserialize(signed["jws"])
        verified.verify(public, alg=algorithm)
        assert verified.payload == payload
        assert verified.jose_header["alg"] == algorithm

        python_key = jwk.JWK.generate(kty="OKP", crv="Ed25519", alg=algorithm)
        produced = jws.JWS(payload)
        produced.add_signature(python_key, protected=json.dumps({"alg": algorithm}))
        result = rust(binary, "verify-compact", algorithm, {
            "jwk": json.loads(python_key.export_public()),
            "jws": produced.serialize(compact=True),
        })
        assert result["ok"]
        assert result["payload_b64u"] == encoded
        assert result["protected_header"]["alg"] == algorithm
        print(f"{algorithm}: Rust -> jwcrypto and jwcrypto -> Rust passed")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: ed25519_jwcrypto.py /path/to/jose-interop")
    main(sys.argv[1])
