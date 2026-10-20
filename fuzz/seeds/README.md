# Fuzz seed corpus

Generated inputs for the harnesses in `fuzz/fuzz_targets/`, committed on purpose.

```sh
cargo run --example fuzz_seeds             # regenerate
cargo run --example fuzz_seeds -- --check  # fail if this directory is stale
```

The generator is `examples/fuzz_seeds.rs`. Output is byte-stable wherever that is
possible: key-file seeds are copies of `tests/fixtures/**` plus the DER decoded out
of their PEM armor, and JWK / JWK Set / claims / HMAC-token seeds use **fixed** key
material and a fixed payload, so even the signature is fixed. Nothing here is a
secret — every key is a constant in the example.

One exception, named in code (`NON_DETERMINISTIC`) rather than papered over: the
`A256GCM` documents in `jwe_json_flattened/`, `jwe_json_general/` and `jwe_decrypt/`
carry a fresh random IV, so their bytes change on every regeneration and `--check`
compares those three directories by file name only. Making them byte-stable would
mean hard-coding an IV, which is a vulnerability encoded as a test fixture — the
whole reason AEAD nonces are random.

## Why seeds are committed

Coverage-guided fuzzing is good at finding shallow refusals from random bytes and
bad at reaching code behind structure. It has to *discover* that a certificate is
four nested sequences before it can exercise the positional walk inside one. The
seeds put the interesting deep inputs in the starting population: a real PEM block
around real DER, a General JWE with a recipient, a claims object whose duplicate
member is the third of five.

A committed corpus is also the difference between a crash report and a regression.
libFuzzer's own discoveries live in `fuzz/corpus/` (gitignored); anything worth
keeping gets moved here, where `tests/fuzz_regressions.rs` replays it on stable in
CI, with mutations, forever.

## Layout

One directory per harness, named exactly like the `[[bin]]` in `fuzz/Cargo.toml`:

| Directory | Contents |
|---|---|
| `base64url_decode/` | alphabet edges: padded, standard-alphabet, odd length, control bytes |
| `jwk_from_json/`, `jwk_thumbprint/` | valid and malformed JWK JSON, `use`/`key_ops` shapes |
| `jwk_from_pem/`, `jwk_from_der/` | armor and DER for PKCS#8, SPKI, SEC1, PKCS#1, and the wrong-label cross products |
| `certificate_extract/` | real certificates, a decoy-SPKI certificate, v1, BER, truncated, a chain, non-RSA keys |
| `encrypted_pkcs8/` | `ENCRYPTED PRIVATE KEY` files, including schemes the allow-list refuses |
| `jwkset_select/` | addressable sets, kid-less, duplicate `kid`, unusable entries, over the entry budget |
| `jwe_json_flattened/`, `jwe_json_general/` | valid documents plus unprotected-`alg` grafts and a rewritten protected header |
| `jwe_decrypt/`, `jws_verify/`, `jws_decode_header/`, `jwt_decode_unverified/` | compact-wire tokens, detached and segment-truncated variants, `alg: none` |
| `jwt_claims/` | duplicate registered members, huge and fractional numerics, `null` versus absent |

## Fixture provenance

Key and certificate files originate in `tests/fixtures/` (see the READMEs there for
how they were created with OpenSSL). They are copied, not edited: if a fixture
changes, `--check` reports the corpus as stale and regeneration picks up the new
bytes.
