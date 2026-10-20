#![no_main]

use libfuzzer_sys::fuzz_target;

// PEM import (RFC 7468 label dispatch). This path is attacker-controlled
// wherever a key is pasted or fetched, and it is the only place that decides
// *which* key format a block of armor claims to be — a wrong dispatch is a
// silent mis-parse, not just an error.
//
// Resource bounds: PEM decoding is armour + base64 only, so the work is
// proportional to input length; the DER-level importers behind it enforce the
// RSA modulus floor and size caps. No password is involved here — encrypted
// armour is refused by name, and `encrypted_pkcs8` fuzzes that path with an
// explicit iteration budget.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Label dispatch (one block only; multiple blocks must be refused, not
    // silently taken in some order).
    if let Ok(jwk) = jose_rs::jwk::pem::jwk_from_pem(text) {
        // Downstream paths a caller would immediately take: conversion,
        // thumbprint, public-only view, and re-export in each explicit format.
        let _ = jose_rs::jwk::jwk_to_software_key(&jwk);
        let _ = jose_rs::jwk::thumbprint::thumbprint_sha256(&jwk);
        let _ = jwk.to_public_jwk();
        let _ = jose_rs::jwk::pem::public_pem_from_jwk(&jwk);
        let _ = jose_rs::jwk::pem::private_pem_from_jwk(&jwk);
    }

    // Format-explicit entry points: the same bytes claimed under a label the
    // caller named. These must refuse mismatches, never guess.
    let _ = jose_rs::jwk::pem::jwk_from_pkcs8_pem(text);
    let _ = jose_rs::jwk::pem::jwk_from_spki_pem(text);
});
