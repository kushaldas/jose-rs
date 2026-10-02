#![no_main]

use libfuzzer_sys::fuzz_target;

// Certificate public-key extraction — the highest-risk parser in the crate,
// because it is the only one that locates a structure *positionally* rather
// than by a caller-supplied label.
//
// `public_jwk_from_certificate_der` walks `Certificate` → `TBSCertificate` →
// `subjectPublicKeyInfo` and decides, from the next tag, whether `version` is
// present. That decision is what shifts every following field index by one, so
// an off-by-one here does not fail: it reads some *other* legitimate-looking
// structure as a public key. A decoy SPKI sitting in a certificate *extension*
// (see `tests/fixtures/cert`) is the case that turns such a bug into a
// wrong-key acceptance, which is why the corpus for this target is seeded with
// real certificates and their mutations rather than random bytes alone.
//
// What this target must never produce: a panic, or an accepted key derived
// from bytes outside the authenticated-structure path we document. It
// deliberately validates nothing else — no signature, no chain, no validity
// period (ADR 0026) — so "accepted" here is not "trusted".
fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }

    if let Ok(jwk) = jose_rs::jwk::cert::public_jwk_from_certificate_der(data) {
        // The located key has to survive the same downstream paths any imported
        // key would: conversion, thumbprint, public export.
        let _ = jose_rs::jwk::jwk_to_software_key(&jwk);
        let _ = jose_rs::jwk::thumbprint::thumbprint_sha256(&jwk);
        let _ = jose_rs::jwk::pem::public_pem_from_jwk(&jwk);
    }

    // PEM armour in front of the same walk, including the path where the
    // decoded bytes are not a certificate at all.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = jose_rs::jwk::cert::public_jwk_from_certificate_pem(text);
    }
});
