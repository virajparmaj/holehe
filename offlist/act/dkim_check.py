"""Does a DKIM signature actually vouch for the unsubscribe headers?

This is the gate that makes automated unsubscribing safe rather than harmful.
POSTing to an unsubscribe URL tells whoever runs it that the address is live,
monitored, and belongs to someone who reads their mail -- which is worth money to
a spammer. RFC 8058 only means anything when the headers carrying that URL are
covered by a signature the sender cannot forge.

Three separate questions, answered separately so a partial pass is never
reported as a full one:

1. Is there a signature at all?
2. Does its ``h=`` tag cover List-Unsubscribe *and* List-Unsubscribe-Post?
3. Does the signature actually verify, and does its ``d=`` domain align with the
   host we would POST to?
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from offlist.act.message import SenderMessage

REQUIRED_HEADERS = ("list-unsubscribe", "list-unsubscribe-post")

_TAG_RE = re.compile(r"(?:^|;)\s*([a-z]+)\s*=\s*([^;]*)", re.I)


@dataclass(frozen=True)
class DkimVerdict:
    present: bool = False
    covers_unsubscribe: bool = False
    signature_valid: bool | None = None      # None = not cryptographically checked
    aligned: bool = False
    signing_domain: str = ""
    detail: str = ""

    @property
    def trustworthy(self) -> bool:
        """Everything must hold. `None` (unchecked) is not a pass."""
        return (self.present and self.covers_unsubscribe
                and self.signature_valid is True and self.aligned)


def parse_tags(signature: str) -> dict[str, str]:
    return {m.group(1).lower(): m.group(2).strip()
            for m in _TAG_RE.finditer(signature.replace("\r\n", "").replace("\n", ""))}


def _domains_align(signing_domain: str, endpoint_host: str) -> bool:
    """The signer must own the endpoint, or be a parent of it.

    A message signed by `mailer.example.com` pointing at `unsub.example.com` is
    fine; one signed by `bulk-sender.test` pointing at `pharma-deals.test` is the
    exact shape we refuse.
    """
    if not signing_domain or not endpoint_host:
        return False
    signing_domain = signing_domain.lower().strip(".")
    endpoint_host = endpoint_host.lower().strip(".")
    if endpoint_host == signing_domain:
        return True

    def registrable(host: str) -> str:
        try:
            import tldextract

            parts = tldextract.extract(host)
            if parts.domain and parts.suffix:
                return f"{parts.domain}.{parts.suffix}"
        except Exception:
            pass
        return ".".join(host.split(".")[-2:])

    return registrable(signing_domain) == registrable(endpoint_host)


def check(message: SenderMessage, *, dnsfunc=None,
          cryptographic: bool = True) -> DkimVerdict:
    """Evaluate a message's DKIM coverage of its unsubscribe headers.

    A message may carry several signatures. We want the first one that actually
    signs the unsubscribe headers; if none does, we report the closest miss so
    the user is told what was wrong rather than just "refused".
    """
    if not message.dkim_signatures:
        return DkimVerdict(detail="no DKIM-Signature header on the message")

    endpoint = message.unsubscribe_host
    near_miss: DkimVerdict | None = None

    for signature in message.dkim_signatures:
        tags = parse_tags(signature)
        signed = {h.strip().lower() for h in (tags.get("h") or "").split(":") if h.strip()}
        signing_domain = (tags.get("d") or "").lower()
        aligned = _domains_align(signing_domain, endpoint)

        missing = [h for h in REQUIRED_HEADERS if h not in signed]
        if missing:
            near_miss = near_miss or DkimVerdict(
                present=True, covers_unsubscribe=False, aligned=aligned,
                signing_domain=signing_domain,
                detail=f"signature by {signing_domain or '?'} does not sign "
                       f"{', '.join(missing)}")
            continue

        if not cryptographic:
            return DkimVerdict(
                present=True, covers_unsubscribe=True, signature_valid=None,
                aligned=aligned, signing_domain=signing_domain,
                detail="header coverage checked; signature not cryptographically verified")

        valid, note = _verify(message.raw, dnsfunc, signature)
        return DkimVerdict(present=True, covers_unsubscribe=True,
                           signature_valid=valid, aligned=aligned,
                           signing_domain=signing_domain, detail=note)

    return near_miss or DkimVerdict(
        present=True, detail="no signature covered the unsubscribe headers")


def _dns_key_present(signature: str, dnsfunc=None) -> bool | None:
    """Is a public key actually published for this selector?

    dkimpy folds a missing DNS record and a bad signature into the same `False`,
    which leaves the user staring at "signature did not verify" when the real
    story is that the sender never published a key. Worth separating: one is the
    sender's misconfiguration, the other is a forgery.
    """
    tags = parse_tags(signature)
    selector, domain = tags.get("s"), tags.get("d")
    if not selector or not domain:
        return None
    name = f"{selector}._domainkey.{domain}"
    try:
        if dnsfunc is not None:
            record = dnsfunc(name)
        else:
            from dkim.dnsplug import get_txt

            record = get_txt(name.encode())
    except Exception:
        return None
    return bool(record and b"p=" in (record if isinstance(record, bytes)
                                     else str(record).encode()))


def _verify(raw: bytes, dnsfunc=None, signature: str = "") -> tuple[bool | None, str]:
    try:
        import dkim as dkimpy
    except ImportError:
        return None, ("dkimpy is not installed, so the signature could not be "
                      "verified -- install offlist[dkim] to enable one-click "
                      "unsubscribe")
    try:
        kwargs = {"dnsfunc": dnsfunc} if dnsfunc is not None else {}
        ok = dkimpy.verify(raw, **kwargs)
    except Exception as exc:
        return False, f"DKIM verification raised {type(exc).__name__}: {exc}"

    if ok:
        return True, "signature verified"

    if signature and _dns_key_present(signature, dnsfunc) is False:
        tags = parse_tags(signature)
        return False, (f"no public key published at "
                       f"{tags.get('s', '?')}._domainkey.{tags.get('d', '?')} "
                       f"-- the sender's DKIM setup is incomplete, so the "
                       f"unsubscribe header cannot be trusted")
    return False, "signature did not verify"
