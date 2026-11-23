# Opt-in RSA-OAEP key transport

Some federation profiles register the RFC 7518 RSA-OAEP algorithm, which uses SHA-1. The `rsa-oaep` feature exposes the existing backend implementation independently of unsecured JWS identifiers. It retains the key size, recipient policy and implicit rejection checks used by RSA-OAEP-256. Existing users of `deprecated` inherit this feature. Default builds continue to reject the identifier.
