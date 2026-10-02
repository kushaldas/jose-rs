# X.509 certificate fixtures (I4)

Generated with **OpenSSL 3.6.2**, then mutated by `build_fixtures.py` (in this directory) for
the adversarial cases. Re-generate with:

```sh
openssl req -x509 -newkey rsa:2048  -keyout rsa_key.pem   -out rsa_cert.pem   -nodes -sha256 -days 3 -subj "/CN=jose-rs RSA test"
openssl req -x509 -newkey ec  -pkeyopt ec_paramgen_curve:P-256 -keyout ec256_key.pem -out ec256_cert.pem -nodes -sha256 -days 3 -subj "/CN=jose-rs EC P-256"
openssl req -x509 -newkey ec  -pkeyopt ec_paramgen_curve:P-384 -keyout ec384_key.pem -out ec384_cert.pem -nodes -sha256 -days 3 -subj "/CN=jose-rs EC P-384"
openssl req -x509 -newkey ed25519                            -keyout ed_key.pem    -out ed_cert.pem    -nodes             -days 3 -subj "/CN=jose-rs Ed25519"
openssl req -x509 -newkey rsa:2048  -keyout rsa2_key.pem   -out rsa2_cert.pem   -nodes -sha256 -days 3 -subj "/CN=jose-rs decoy"
openssl req -x509 -newkey ec  -pkeyopt ec_paramgen_curve:brainpoolP256r1 -keyout bp_key.pem -out bp_cert.pem -nodes -sha256 -days 3 -subj "/CN=Brainpool"
openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -out dsa_params.pem
openssl genpkey -paramfile dsa_params.pem -out dsa_key.pem
openssl req -x509 -new -key dsa_key.pem -out dsa_cert.pem -sha256 -days 3 -subj "/CN=DSA"
for f in rsa ec256 ec384 ed rsa2; do openssl x509 -in ${f}_cert.pem -pubkey -noout > ${f}_spki.pem; done
openssl x509 -in rsa_cert.pem -outform DER -out rsa_cert.der
cat rsa_cert.pem ec256_cert.pem > chain.pem
python3 build_fixtures.py
```

| file | what it is | why it is here |
| --- | --- | --- |
| `rsa_cert.pem`, `rsa_cert.der`, `ec256_*`, `ec384_*`, `ed_*` | ordinary self-signed v3 certificates | the happy path, cross-checked against `*_spki.pem` (OpenSSL's own SPKI of the same cert) |
| `*_key.pem` | the matching private keys | a signature made with them must **verify** under the cert-extracted key — the only check that rules out reading the wrong element |
| `rsa_cert_v1.pem` | `[0] version` element deleted (v1-shaped) | `subjectPublicKeyInfo` shifts index when `version` is absent |
| `rsa_cert_decoy.pem` | a second, valid SPKI inside a private extension | a reader that *searches* for a public key picks the decoy; a positional reader must not |
| `rsa_cert_ber_inner.pem`, `rsa_cert_ber_outer.pem` | indefinite-length `tbsCertificate` / outer `SEQUENCE` | DER (RFC 5280 A.1) forbids these; OpenSSL accepts them, `cryptography` refuses them, and so do we |
| `rsa_cert_truncated.pem` | cut in half | length/value mismatch must be caught, not read past |
| `rsa_cert_tampered.pem` | one bit flipped in `signatureValue` | pins that extraction does **not** validate: same key out, always |
| `chain.pem` | two `CERTIFICATE` blocks | refused with a block count rather than silently using block one |
| `dsa_cert.pem`, `bp_cert.pem`, `rsa_pss_spki.pem` | DSA key, Brainpool curve, `id-RSASSA-PSS` SPKI | unsupported/restricted algorithms must fail clearly |

`rsa_cert_ber_inner.pem`, `rsa_cert_ber_outer.pem`, `rsa_cert_decoy.pem`, `rsa_cert_v1.pem` and
`rsa_cert_tampered.pem` are all still *parseable* by OpenSSL (`tampered` verifies as invalid, but
loads), which is the point: our refusals and our non-refusals are policy choices about what a key
extractor may assume, not artifacts of broken input.

Test keys with short lifetimes. Never reuse these key files.
