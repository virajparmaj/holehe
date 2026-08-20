# offlist

**Find which services hold your email address, and get a worklist for making them delete it.**

A hard fork of [megadose/holehe](https://github.com/megadose/holehe). The original
answers "is this email registered on site X". This answers a different question:
*which sites hold my address that shouldn't, and how do I get off their list?*

---

## Why the fork

I instrumented the original and ran all 123 site modules against a live network,
logging every HTTP exchange.

| | |
|---|---|
| Modules that returned no usable answer | **76 of 123** |
| Of those, genuine HTTP 429 rate limits | **2** |
| Modules that provably distinguish a real address from a fake one | **21** |

Every one of those 76 failures was reported to the user as `[x] Rate limit`,
because each module funnelled every failure — dead endpoints, WAF blocks, dead
hosts, changed response formats — through a single `rateLimit` boolean set from a
bare `except Exception`.

Throttling does not fix it. Re-running gated at 4 concurrent requests with jitter
left 67 of 69 unchanged: every module talks to a different host, so global
concurrency was never the constraint.

Worse, a control run against a fabricated address showed 26 modules answering
"not used" for *everything*, including `amazon`, `wordpress`, `gravatar` and
`quora` for `test@gmail.com`. There was no test suite, so that had been true for
years without anyone noticing.

## What changed

**Failures name their real cause.** `rateLimit: bool` became a status enum —
`rate_limited`, `blocked`, `endpoint_gone`, `unreachable`, `server_error`,
`parse_failed`. Each one implies a different fix: retry, change client, or fix
the definition in this repo.

**A negative has to be earned.** Every site records whether a canary has ever
proven it distinguishes a real address from a fabricated one. If it hasn't, its
"no account here" is reported as `indeterminate`, not as an answer.

**Sites are data, not code.** 25 of the original modules were byte-identical MyBB
forum clones differing only in a base URL — roughly 2,000 lines that are now one
engine and 25 one-line rows.

**Probing is one source of six.** The others are better at the actual question:

| Source | Question it answers | Precision |
|---|---|---|
| Vault CSV import | Where did I *deliberately* sign up? | exact, offline |
| Mailbox evidence | Where did I get a welcome/verification/reset mail? | high, offline, dated |
| Data-broker registry | Who holds my data that I never gave them? | exact — registration is compulsory |
| Public exposure | Where is my address publicly readable? | high |
| Breach data (HIBP) | Who has already lost my address? | high, opt-in, k-anonymous |
| Endpoint probing | Accounts I forgot, or never made | low until canary-verified |

Every source emits only dated evidence; a per-service **confidence score (0–100)**
and one of four association states — `confirmed`, `likely`, `exposure`,
`unknown` — is computed from that evidence in one place. `unknown` means
*insufficient evidence*, never "no account".

## Install

```bash
pip install .
```

## Use

Probe the catalogue for one address:

```bash
offlist scan you@example.com
```

Catalogue health, no network:

```bash
offlist doctor
```

Pull the statutory data-broker registry (~600 companies, refreshed annually):

```bash
offlist brokers refresh
```

Import a password-manager export — 1Password, Bitwarden, Chrome, Firefox:

```bash
offlist import you@example.com ~/Downloads/export.csv
```

Build the removal worklist. `--mail` reads your own saved mail (`.eml`, mbox, or
maildir) for welcome/verification/reset messages — the strongest, and dated,
forgotten-account signal, entirely offline:

```bash
offlist worklist you@example.com --vault ~/Downloads/export.csv --mail ~/saved-mail/ --jurisdiction CA --format md
```

Work through the plan. Dry run by default — nothing leaves your machine:

```bash
offlist act you@example.com --mail ~/saved-mail/ --jurisdiction CA
```

Actually do it, with a separate yes for each item:

```bash
offlist act you@example.com --mail ~/saved-mail/ --execute
```

Check the catalogue still works and record what that proved:

```bash
offlist canary --positives offlist/catalogue/canary/public_positives.yaml --write-ledger
```

## The worklist

Each entry says why it is there, what the evidence was and when it was observed,
and the exact route to removal — a deletion URL, an opt-out form, a one-click
unsubscribe, or a generated GDPR/CCPA letter.

The flag that matters most is `never_signed_up`: something can prove a service
holds your address, and your own credential store has no record of you creating
an account there.

Evidence is append-only, so the file doubles as an audit log. Conflicting
evidence is kept side by side rather than resolved — "the probe says no account,
your vault says you have a password there" is itself a finding.

## Adding a site

Sites live in `offlist/catalogue/sites/*.yaml`:

```yaml
- id: example
  domain: example.com
  category: social_media
  method: register
  steps:
    - id: check
      method: GET
      url: https://example.com/api/email-available
      params: { email: "{email}" }
  rules:
    - when: { json: { path: taken, equals: true } }
      then: registered
    - when: { json: { path: taken, equals: false } }
      then: not_registered
```

There is no implicit "not registered". A definition that falls off the end of its
rules reports `parse_failed`, because reaching the end means the site said
something you have never seen. Claiming a negative needs a rule that matched.

Sites sharing a platform share an engine (`offlist/catalogue/engines/`), so a new
MyBB forum is one line.

## Acting on the worklist

`offlist act` turns each worklist entry into a concrete step and shows you
exactly what it would do. Four outcomes:

| | |
|---|---|
| **one-click unsubscribe** | The only thing the tool performs itself, and only when a DKIM signature proves the sender vouches for the unsubscribe URL. |
| **letters** | A GDPR Art.17 / CCPA §1798.105 deletion request, written to disk. You send it. |
| **URLs** | Opt-out forms and account-deletion pages. The tool hands you the link and stays out of the way. |
| **nothing known** | An honest gap, and a TODO for `offlist/data/remediation.yaml`. |

### Why unsubscribing needs a signature

POSTing to an unsubscribe URL tells whoever runs it that your address is live,
monitored, and belongs to someone who reads their mail. For a real newsletter
that is fine. For a spammer it is a favour, and it makes things worse.

RFC 8058 one-click only means something when the headers carrying that URL are
covered by a DKIM signature the sender cannot forge. So `offlist act` checks
three separate things and requires all of them:

1. a signature exists and its `h=` tag covers `List-Unsubscribe` **and**
   `List-Unsubscribe-Post`;
2. the signature actually verifies;
3. the signing domain owns the host you would POST to — a validly signed message
   from `bulk-sender.test` pointing at `pharma-deals.test` is refused.

Anything short of all three is refused with the reason spelled out. "Could not
check" is reported separately from "checked and failed", and an unverified
signature never counts as a pass. Without `offlist[dkim]` installed the feature
degrades to *refused with an explanation*, never to *sent unchecked*.

Messages come from `--mail`, which reads `.eml` files, mbox files, or a maildir —
drag them out of any mail client. Phase 8 will feed the same parser over OAuth.

## Safety

Some probes have side effects, and they are off unless you ask for them:

- **`--allow-login-probe`** — seven checks submit a deliberately wrong password.
  That increments failed-login counters and feeds fraud scoring; you can lock
  yourself out of your own account running your own audit.
- **`--allow-email-sending`** — four checks trigger a real password-recovery
  email to the address.

Both additionally require `--i-own-this`. Probes that would create an account are
never selectable.

`offlist worklist` and `offlist act` are read-only until you pass `--execute`,
and `--execute` asks about each item on its own, showing the literal request
first. There is no `--yes-to-all`: those flags exist solely so the tool can
refuse them and explain why. Running `--execute` without a terminal is refused
too, so it cannot sail through prompts in a cron job.

Deletion letters are generated, never sent. There is no SMTP client anywhere in
`offlist/act/`, and a test asserts one never appears — a tool that can mail on
your behalf is a bulk sender operating under your identity, and a misfire leaves
no audit trail.

The worklist file is a concentrated dossier — every service you use, which have
been breached, which leak recovery identifiers. It is stored under
`~/.local/state/offlist/`, mode `0600`, with the address hashed into the path
rather than written into a filename.

HIBP is queried through its k-anonymity range endpoint by default: only the
first six characters of your address's SHA-1 hash leave the machine, and the
match is finished locally, so the address itself is never disclosed. The breach
names that come back are joined against HIBP's public catalogue to recover the
same detail the plaintext endpoint returns. `--hibp-plaintext` opts back into
sending the whole address; either way nothing is queried without an explicit key
(`offlist worklist --explain-hibp`).

## What this is not

- **Not a 3,000-site scanner.** The measurement above is the argument: 60
  canary-green sites beat 500 unknown ones.
- **Not a third-party OSINT tool.** Batch address input is refused by default.
- **Not an auto-remediator.** It produces a worklist; you act on it.
- **Not a DROP client.** California's Delete Act platform is consumer
  authenticated and resident-only; the tool reports coverage and links you there.

## Migration status

`offlist doctor` reports it. The original modules still run through a legacy
bridge, which classifies their failures by what the server actually did rather
than by their own `rateLimit` boolean. Entries move to declarative definitions
one at a time; `tests/test_legacy_core.py` pins the crash-level fixes until the
old tree is deleted.

## Licence

GPLv3, inherited from holehe. The original README is kept as
`README.holehe-original.md`, and the original credits stand — this is a fork of
their work, not a replacement for it.
