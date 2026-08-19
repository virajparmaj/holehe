"""Build genuinely DKIM-signed messages, verifiable offline.

A fake "this looks signed" fixture would test nothing: the whole point of the
gate is that a signature cannot be forged. These are real RSA signatures, checked
against a public key handed to dkimpy through an injected dnsfunc.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DEFAULT_HEADERS = [b"from", b"to", b"subject",
                   b"list-unsubscribe", b"list-unsubscribe-post"]


@dataclass
class SignedFixture:
    raw: bytes
    dnsfunc: object


def _keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption())
    pub = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem, base64.b64encode(pub).decode()


def build_message(*, sender="news@mail.shop.test",
                  unsubscribe="<https://unsub.shop.test/u/abc>, <mailto:u@shop.test>",
                  one_click=True, subject="Weekly deals") -> bytes:
    headers = [
        f"From: {sender}",
        "To: you@example.com",
        f"Subject: {subject}",
    ]
    if unsubscribe:
        headers.append(f"List-Unsubscribe: {unsubscribe}")
    if one_click:
        headers.append("List-Unsubscribe-Post: List-Unsubscribe=One-Click")
    return ("\r\n".join(headers) + "\r\n\r\nHello.\r\n").encode()


def sign(raw: bytes, *, domain="mail.shop.test", include_headers=None,
         wrong_key=False) -> SignedFixture:
    pem, pub = _keypair()
    signature = dkim.sign(raw, b"sel", domain.encode(), pem,
                          include_headers=include_headers or DEFAULT_HEADERS)

    if wrong_key:
        # Publish a different public key, so the signature is well-formed but
        # cannot verify -- the forged-message case.
        _, pub = _keypair()

    def dnsfunc(name, timeout=5):
        return f"v=DKIM1; k=rsa; p={pub}".encode()

    return SignedFixture(raw=signature + raw, dnsfunc=dnsfunc)


def unsigned(**kwargs) -> SignedFixture:
    def dnsfunc(name, timeout=5):
        return b""
    return SignedFixture(raw=build_message(**kwargs), dnsfunc=dnsfunc)
