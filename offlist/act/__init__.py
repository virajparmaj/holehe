"""Outward-facing actions.

Everything in this package does something a third party can see, in the user's
name, that cannot be taken back. The rules are enforced in code, not documented
as guidance:

* Nothing is sent without ``--execute`` *and* an interactive yes for that
  specific item. There is no ``--yes-to-all``, and running without a TTY refuses
  to execute rather than assuming consent.
* A one-click unsubscribe is only offered when a DKIM signature actually covers
  the List-Unsubscribe headers and the signing domain aligns with the endpoint.
  Otherwise the POST would just confirm to a spammer that the address is live.
* Deletion letters are written to disk. There is no SMTP code anywhere in this
  package, so "send it anyway" is not one keystroke away.
"""
