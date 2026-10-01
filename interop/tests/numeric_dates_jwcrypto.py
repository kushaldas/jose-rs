"""Check fractional JWT interoperability using disposable in-memory Ed25519 keys.

Pass the built jose-interop executable as the sole argument. Fractions in
these fixtures are exactly representable by Python floats; higher decimal
precision and boundary validation are covered by Rust integration tests.
"""

import json
import sys

from jwcrypto import jwk, jwt
from ed25519_jwcrypto import rust


def main(binary: str) -> None:
    """Verify both producers preserve fractional dates in signed JWT claims."""
    algorithm = "Ed25519"
    claims = {"exp": 4102444800.125, "nbf": 1.25, "iat": 2.5}
    rust_key = rust(binary, "gen-key", algorithm, {})
    produced = rust(binary, "sign-jwt", algorithm, {"jwk": rust_key, "claims": claims})
    verified = jwt.JWT(key=jwk.JWK(**rust_key).public(), jwt=produced["jwt"],
                       algs=[algorithm], expected_type="JWS")
    assert json.loads(verified.claims) == claims

    python_key = jwk.JWK.generate(kty="OKP", crv="Ed25519", alg=algorithm)
    signed = jwt.JWT(header={"alg": algorithm}, claims=claims)
    signed.make_signed_token(python_key)
    result = rust(binary, "verify-jwt", algorithm, {
        "jwk": json.loads(python_key.export_public()), "jwt": signed.serialize(),
    })
    assert result["ok"]
    assert result["claims"] == claims
    print("Fractional JWT dates: Rust -> jwcrypto and jwcrypto -> Rust passed")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: numeric_dates_jwcrypto.py /path/to/jose-interop")
    main(sys.argv[1])
