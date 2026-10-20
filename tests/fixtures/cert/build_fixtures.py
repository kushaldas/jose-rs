#!/usr/bin/env python3
"""Build the adversarial X.509 fixtures for I4 (see tests/fixtures/cert/README.md).

Everything here is raw DER surgery on OpenSSL-produced certificates: no X.509 library, because
the point is to control the exact bytes a *parser* sees (a library would re-encode canonically
and lose the BER/indefinite-length and version-shift cases).
"""
import pathlib
import subprocess
import sys

OUT = pathlib.Path("/tmp/certfix")


def tlv_read(data, offset=0):
    tag = data[offset]
    offset += 1
    first = data[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7F
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    else:
        length = first
    return tag, data[offset:offset + length], offset + length


def tlv_elements(body):
    out, offset = [], 0
    while offset < len(body):
        tag, value, offset = tlv_read(body, offset)
        # Reconstruct the full TLV including header for callers that need it.
        out.append((tag, value))
    return out


def encode(tag, body):
    length = len(body)
    if length < 0x80:
        head = bytes([tag, length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        head = bytes([tag, 0x80 | len(raw)]) + raw
    return head + body


def encode_sequence(tag, elements):
    return encode(tag, b"".join(elements))


def cert_parts(pem_path):
    der = subprocess.run(
        ["openssl", "x509", "-in", str(pem_path), "-outform", "DER"],
        capture_output=True, check=True,
    ).stdout
    _, cert_body, _ = tlv_read(der)
    elements = tlv_elements(cert_body)
    return der, elements


def main():
    der, elements = cert_parts(OUT / "rsa_cert.pem")
    tbs_tag, tbs_body = elements[0]
    tbs_elements = tlv_elements(tbs_body)
    assert tbs_elements[0][0] == 0xA0, "expected a v3 certificate with [0] version"

    # 1) A version-1-shaped certificate: the [0] version element removed. Everything else is
    #    byte-identical, so the only thing a reader can rely on is position — and the position
    #    of subjectPublicKeyInfo *shifts* when version is absent.
    slim_tbs_elements = tbs_elements[1:]
    slim_tbs = encode_sequence(tbs_tag, [encode_tag_value(t, v) for t, v in slim_tbs_elements])
    slim_cert = encode_sequence(0x30, [slim_tbs] + [encode_tag_value(t, v) for t, v in elements[1:]])
    (OUT / "rsa_cert_v1.der").write_bytes(slim_cert)
    write_pem(OUT / "rsa_cert_v1.pem", slim_cert, "CERTIFICATE")

    # 2) A decoy: a private extension whose value is a *different, valid* SPKI. A reader that
    #    searches for "something that looks like a public key" picks the wrong key here; a
    #    reader that walks to the right position does not.
    subprocess.run(
        ["openssl", "x509", "-in", str(OUT / "rsa2_cert.pem"), "-pubkey", "-noout"],
        stdout=open(OUT / "rsa2_spki.pem", "w"), check=True,
    )
    decoy_der = subprocess.run(
        ["openssl", "pkey", "-pubin", "-pubout", "-outform", "DER",
         "-in", str(OUT / "rsa2_spki.pem")],
        capture_output=True, check=True,
    ).stdout
    # OID 1.3.6.1.4.1.99999.1, non-critical, value = OCTET STRING wrapping the decoy SPKI.
    oid = bytes.fromhex("2b060104018a8f1f01")  # 1.3.6.1.4.1.99999.1
    extension = encode_sequence(0x30, [
        encode(0x06, oid),
        encode(0x01, b"\x00"),                # critical FALSE
        encode(0x04, decoy_der),               # extn value: a complete, valid SPKI
    ])
    # The extensions live in tbs element [3]; find it and append our extension.
    new_tbs_elements = []
    for tag, value in tbs_elements:
        if tag == 0xA3:
            inner = tlv_elements(value)[0]  # SEQUENCE of extensions
            new_inner = encode_sequence(0x30, [encode_tag_value(*e) for e in tlv_elements(inner[1])] + [extension])
            new_tbs_elements.append(encode(tag, new_inner))
        else:
            new_tbs_elements.append(encode(tag, value))
    decoy_tbs = encode_sequence(0x30, new_tbs_elements)
    decoy_cert = encode_sequence(0x30, [decoy_tbs] + [encode_tag_value(t, v) for t, v in elements[1:]])
    (OUT / "rsa_cert_decoy.der").write_bytes(decoy_cert)
    write_pem(OUT / "rsa_cert_decoy.pem", decoy_cert, "CERTIFICATE")

    # 3) BER, not DER: indefinite-length constructed values. Legal BER, illegal DER (RFC 5280
    #    A.1 requires definite lengths). Done surgically rather than by a recursive rewrite, so
    #    the file is exactly one mutation away from a real certificate: the length header of the
    #    tbsCertificate (and, in the second fixture, of the outermost SEQUENCE) becomes 0x80 and
    #    an end-of-contents marker is appended. Two fixtures, because the outer case is caught by
    #    the first length read and the inner case only by walking into the certificate.
    outer = indefinite_outer(der)
    (OUT / "rsa_cert_ber_outer.der").write_bytes(outer)
    write_pem(OUT / "rsa_cert_ber_outer.pem", outer, "CERTIFICATE")
    ber = indefinite_tbs(der)
    (OUT / "rsa_cert_ber_inner.der").write_bytes(ber)
    write_pem(OUT / "rsa_cert_ber_inner.pem", ber, "CERTIFICATE")

    # 4) Truncated: cut mid-body so a length/value mismatch is the only defect.
    (OUT / "rsa_cert_truncated.der").write_bytes(der[: len(der) // 2])
    write_pem(OUT / "rsa_cert_truncated.pem", der[: len(der) // 2], "CERTIFICATE")

    # Reference: OpenSSL's own view of the real subject key, as SPKI.
    subprocess.run(["openssl", "x509", "-in", str(OUT / "rsa_cert.pem"), "-pubkey", "-noout"],
                   stdout=open(OUT / "rsa_spki_reference.pem", "w"), check=True)

    for name in ("rsa_cert_v1", "rsa_cert_decoy", "rsa_cert_ber", "rsa_cert_ber_outer",
                 "rsa_cert_truncated"):
        info = subprocess.run(["openssl", "x509", "-in", f"{OUT}/{name}.pem", "-noout", "-text"],
                              capture_output=True)
        status = "openssl accepts" if info.returncode == 0 else "openssl refuses: " + info.stderr.decode().strip().splitlines()[0][:70]
        print(f"{name:22} {len((OUT / f'{name}.der').read_bytes()):6} bytes  {status}")


def encode_tag_value(tag, value):
    """Re-encode an element captured by tlv_elements (which drops the header)."""
    return encode(tag, value)


def indefinite_outer(der):
    """The whole certificate as an indefinite-length SEQUENCE (caught by the first read)."""
    _, body, _ = tlv_read(der)
    return bytes([0x30, 0x80]) + body + b"\x00\x00"


def indefinite_tbs(der):
    """Only tbsCertificate becomes an indefinite-length SEQUENCE; everything else is DER."""
    _, cert_body, _ = tlv_read(der)
    elements = tlv_elements(cert_body)
    rebuilt = bytearray()
    for index, (tag, value) in enumerate(elements):
        if index == 0:
            rebuilt += bytes([0x30, 0x80]) + value + b"\x00\x00"
        else:
            rebuilt += encode_tag_value(tag, value)
    return encode(0x30, bytes(rebuilt))


def to_ber_indefinite(data):
    """Re-encode constructed elements with indefinite lengths (BER), leaving primitives alone."""
    tag = data[0]
    if not (tag & 0x20):
        # Primitive: keep verbatim.
        _, _, end = tlv_read(data)
        return data[:end]
    _, body, _ = tlv_read(data)
    if tag == 0x04 and body[:1] in (b"\x30",):
        # OCTET STRING contents are opaque; do not re-parse them.
        return encode(tag, body)
    out = bytearray([tag, 0x80])
    offset = 0
    while offset < len(body):
        inner_tag = body[offset]
        piece = to_ber_indefinite(body[offset:])
        _, _, end = tlv_read(body, offset)
        out += piece
        offset += end
    out += b"\x00\x00"
    return bytes(out)


def write_pem(path, der, label):
    import base64
    b64 = base64.b64encode(der).decode()
    wrapped = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    path.write_text(f"-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----\n")


if __name__ == "__main__":
    sys.exit(main())
