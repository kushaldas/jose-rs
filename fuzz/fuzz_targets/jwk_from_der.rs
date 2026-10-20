#![no_main]

use libfuzzer_sys::fuzz_target;

// DER key importers, each format-explicit: PKCS#8, SPKI, PKCS#1 (private and
// public) and SEC1.
//
// PKCS#1 and SEC1 are the interesting ones. Both **rebuild** the key from the
// parsed components and then re-encode it as PKCS#8 to run it through the one
// shared importer, checking the file's own CRT parameters against the rebuild
// instead of trusting either. That is a hand-written DER walk plus arithmetic
// invariants (primes multiply to the modulus, `d*e ≡ 1 mod p-1`, the public
// point derives from the scalar) — exactly the kind of code where a missing
// bound shows up as a panic or a wrong-but-accepted key.
//
// Every importer also refuses things it must refuse: multi-prime RSA (no JWK
// member for a third factor), explicit EC curve parameters, unsupported named
// curves. A refusal that names the member is the expected outcome; a panic is
// the finding.
fuzz_target!(|data: &[u8]| {
    // Bound the work independently of libFuzzer's own limits: DER parsing is
    // linear, but the rebuilds below do bignum arithmetic on the parsed
    // components, so an unbounded allocation in a fuzz run would be attributed
    // to the fuzzer rather than to us.
    if data.len() > 65_536 {
        return;
    }

    let _ = jose_rs::jwk::import::jwk_from_pkcs8_der(data);
    let _ = jose_rs::jwk::import::jwk_from_spki_der(data);

    for result in [
        jose_rs::jwk::import::jwk_from_pkcs1_der(data),
        jose_rs::jwk::import::jwk_from_pkcs1_public_der(data),
        jose_rs::jwk::import::jwk_from_sec1_der(data),
    ]
    .into_iter()
    .flatten()
    {
        // Reaching here means the file's claims were checked and agreed;
        // downstream conversions must not be the place that disagrees.
        let _ = jose_rs::jwk::jwk_to_software_key(&result);
        let _ = jose_rs::jwk::thumbprint::thumbprint_sha256(&result);
        let _ = jose_rs::jwk::pem::public_pem_from_jwk(&result);
    }
});
