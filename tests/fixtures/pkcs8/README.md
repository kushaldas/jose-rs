# Encrypted PKCS#8 fixtures (I3)

Generated with **OpenSSL 3.6.2**, from the EC P-256 key in `../pem/ec_pkcs8.pem` and the RSA
key shown below. Every file is re-generable with the commands here; if a test starts failing
after an OpenSSL upgrade, re-run these and read the diff before touching the assertions.

```sh
# the source keys
openssl ecparam -name prime256v1 -genkey -noout -out ec_sec1.pem
openssl ec -in ec_sec1.pem -outform PEM -out /dev/null            # sanity check
openssl pkcs8 -topk8 -inform PEM -in ec_sec1.pem -nocrypt -out ec_pkcs8.pem
openssl genrsa -out rsa_pkcs8.pem 2048

# enc_pbkdf2_sha256_aes256.pem — OpenSSL's default PBES2 form
openssl pkcs8 -topk8 -in ec_pkcs8.pem -out enc_pbkdf2_sha256_aes256.pem \
    -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout pass:hunter2

# enc_pbkdf2_sha256_aes128.pem — AES-128-CBC, 100 000 iterations
openssl pkcs8 -topk8 -in ec_pkcs8.pem -out enc_pbkdf2_sha256_aes128.pem \
    -v2 aes-128-cbc -v2prf hmacWithSHA256 -iter 100000 -passout pass:hunter2

# enc_rsa_des3.pem — 3DES, which this crate refuses by name
openssl pkcs8 -topk8 -in rsa_pkcs8.pem -out enc_rsa_des3.pem -v2 des3 -passout pass:hunter2

# enc_pbkdf2_sha1_aes256.pem — HMAC-SHA1 PRF, outside the allow-list
openssl pkcs8 -topk8 -in ec_pkcs8.pem -out enc_pbkdf2_sha1_aes256.pem \
    -v2 aes-256-cbc -v2prf hmacWithSHA1 -passout pass:hunter2

# enc_low_iter.pem — one iteration, below this crate's floor
openssl pkcs8 -topk8 -in ec_pkcs8.pem -out enc_low_iter.pem \
    -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 1 -passout pass:hunter2
```

Two measured facts these fixtures encode:

* `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256` and `cryptography`'s
  `BestAvailableEncryption` **both** write 2 048 iterations (`0x0800`) by default, which is why
  `PKCS8_MIN_ITERATIONS` is 2 048 and not some safer number.
* OpenSSL still *accepts* `-iter 1` and `-v2 des`, so `enc_low_iter.pem` and DES-family files
  are real things a user can hand this library.

These are test keys. The passwords are not secrets and must never be reused.
