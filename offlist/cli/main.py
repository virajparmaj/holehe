"""offlist command line.

Subcommands are split by what they touch: `scan` and `canary` hit the network,
`doctor` and `import` do not, and `act` is the only one that ever sends anything
outward -- and it asks first, per item.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

from offlist import __version__
from offlist.core.email import EmailAddress, InvalidEmail
from offlist.sources.base import RunContext


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="offlist",
        description="Find which services hold your email address, and how to make them delete it.",
    )
    parser.add_argument("--version", action="version", version=f"offlist {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- scan
    scan = sub.add_parser("scan", help="probe the site catalogue for one address")
    scan.add_argument("email", help="the address to check -- yours")
    scan.add_argument("--only", action="append", default=[],
                      help="restrict to a site id or category (repeatable)")
    scan.add_argument("--include-disabled", action="store_true",
                      help="also probe entries the ledger has marked dead")
    scan.add_argument("--only-found", action="store_true",
                      help="print only sites where an account was found")
    scan.add_argument("--no-color", action="store_true")
    scan.add_argument("-v", "--verbose", action="store_true",
                      help="show per-site detail and disabled entries")
    scan.add_argument("-T", "--timeout", type=float, default=15.0)
    scan.add_argument("-c", "--concurrency", type=int, default=16)
    scan.add_argument("--csv", metavar="PATH", nargs="?", const="auto")
    scan.add_argument("--json", metavar="PATH", nargs="?", const="auto")
    scan.add_argument("--i-own-this", action="store_true",
                      help="confirm the address is yours; required for probes with side effects")
    scan.add_argument("--allow-login-probe", action="store_true",
                      help="allow probes that submit a wrong password (can lock you out)")
    scan.add_argument("--allow-email-sending", action="store_true",
                      help="allow probes that trigger a real password-recovery email")
    scan.add_argument("-NP", "--no-password-recovery", action="store_true")

    # ---- import
    imp = sub.add_parser("import", help="import a password-manager or browser CSV export")
    imp.add_argument("email", help="the address to build a worklist for")
    imp.add_argument("paths", nargs="+", metavar="CSV",
                     help="1Password / Bitwarden / Chrome / Firefox export(s)")

    # ---- worklist
    work = sub.add_parser("worklist",
                          help="collect evidence from every source and produce a removal plan")
    work.add_argument("email")
    work.add_argument("--format", choices=["term", "md", "json"], default="term")
    work.add_argument("-o", "--output", metavar="PATH")
    work.add_argument("--vault", action="append", default=[], metavar="CSV",
                      help="password-manager export (repeatable)")
    work.add_argument("--jurisdiction", default="", metavar="CA|EU|UK",
                      help="selects which statutory deletion right applies")
    work.add_argument("--skip-probe", action="store_true",
                      help="use stored evidence rather than re-probing the catalogue")
    work.add_argument("--hibp-key", metavar="KEY",
                      help="Have I Been Pwned API key (see --explain-hibp)")
    work.add_argument("--explain-hibp", action="store_true",
                      help="explain what querying HIBP discloses, then exit")
    work.add_argument("--include-all-brokers", action="store_true",
                      help="list all ~600 registered brokers individually instead of "
                           "one DROP-covered aggregate")
    work.add_argument("-T", "--timeout", type=float, default=15.0)

    # ---- act
    act = sub.add_parser(
        "act",
        help="work through the removal plan (dry run unless --execute)")
    act.add_argument("email")
    act.add_argument("--execute", action="store_true",
                     help="actually send, asking about each item individually")
    act.add_argument("--mail", action="append", default=[], metavar="PATH",
                     help=".eml file, mbox, or maildir -- supplies the signed "
                          "List-Unsubscribe headers (repeatable)")
    act.add_argument("--letters-dir", metavar="DIR", default="offlist-letters",
                     help="where generated deletion letters are written")
    act.add_argument("--jurisdiction", default="", metavar="CA|EU|UK")
    act.add_argument("--name", default="", help="your name, for the letter signature")
    act.add_argument("--only", action="append", default=[], metavar="SERVICE",
                     help="restrict to one service (repeatable)")
    act.add_argument("-T", "--timeout", type=float, default=20.0)
    # Present so the refusal is explicit and explained, rather than an
    # "unrecognized argument" that reads like an oversight.
    for flag in ("--yes", "-y", "--yes-to-all", "--all", "--force"):
        act.add_argument(flag, action="store_true", dest="bulk_consent",
                         help=argparse.SUPPRESS)

    # ---- brokers
    brokers = sub.add_parser("brokers", help="manage the statutory data-broker registry")
    brokers.add_argument("action", choices=["refresh", "show"])
    brokers.add_argument("--url", default=None, help="override the registry URL")

    # ---- canary
    canary = sub.add_parser(
        "canary",
        help="check every entry still works, and record what that proved")
    canary.add_argument("--only", action="append", default=[],
                        help="restrict to a site id or category (repeatable)")
    canary.add_argument("--include-disabled", action="store_true",
                        help="also re-check disabled entries, so revivals get noticed")
    canary.add_argument("--positives", metavar="PATH",
                        help="YAML of {site_id: address} known-registered addresses (tier A/B)")
    canary.add_argument("--write-ledger", action="store_true",
                        help="persist the outcome to catalogue/ledger.yaml")
    canary.add_argument("-T", "--timeout", type=float, default=20.0)
    canary.add_argument("-c", "--concurrency", type=int, default=8)

    # ---- doctor
    doctor = sub.add_parser("doctor", help="catalogue health, without touching the network")
    doctor.add_argument("--by", choices=["status", "category"], default="status")

    return parser


def _resolve_email(raw: str) -> EmailAddress:
    try:
        return EmailAddress(raw)
    except InvalidEmail as exc:
        sys.exit(f"[-] {exc}\nExample: offlist scan you@example.com")


def cmd_scan(args: argparse.Namespace) -> int:
    from offlist.cli import render_csv, render_json, render_terminal
    from offlist.sources.probe import run_probes

    email = _resolve_email(args.email)

    # Login probes submit a deliberately wrong password and recovery probes send
    # a real email. Both are fine against your own address and are not fine
    # against anyone else's, so they need an explicit ownership claim.
    if (args.allow_login_probe or args.allow_email_sending) and not args.i_own_this:
        sys.exit("[-] --allow-login-probe / --allow-email-sending need --i-own-this.\n"
                 "    These probes submit failed logins or send real mail to the address.")

    ctx = RunContext(
        timeout=args.timeout,
        concurrency=args.concurrency,
        include_disabled=args.include_disabled,
        allow_login_probe=args.allow_login_probe,
        allow_email_sending=args.allow_email_sending,
        no_password_recovery=args.no_password_recovery,
        only=tuple(args.only),
    )

    started = time.time()
    results = asyncio.run(run_probes(email, ctx, show_progress=not args.only_found))
    elapsed = time.time() - started

    print(render_terminal.render(results, str(email), elapsed,
                                 color=not args.no_color,
                                 only_found=args.only_found,
                                 verbose=args.verbose))

    stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    if args.csv:
        path = Path(f"offlist_{stamp}_results.csv") if args.csv == "auto" else Path(args.csv)
        print(f"\nCSV written to {render_csv.write(results, path)}")
    if args.json:
        path = Path(f"offlist_{stamp}_results.json") if args.json == "auto" else Path(args.json)
        print(f"JSON written to {render_json.write(results, str(email), elapsed, path)}")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    from offlist.sources.vault_csv import collect_sync, vault_domains
    from offlist.worklist import merge, remediation, store, triage

    email = _resolve_email(args.email)
    paths = [Path(p) for p in args.paths]
    missing = [p for p in paths if not p.is_file()]
    if missing:
        sys.exit(f"[-] no such file: {', '.join(str(p) for p in missing)}")

    evidence = collect_sync(email, paths)
    domains = vault_domains(paths)
    records = triage.triage(merge.merge(evidence, vault_domains=domains))
    records = remediation.attach(records)
    merged = store.merge_with_history(email, records)
    path = store.save(email, merged)

    print(f"read {len(domains)} distinct domains from {len(paths)} export(s)")
    print(f"{len(evidence)} of them are stored under {email}")
    print(f"worklist saved to {path} (mode 0600)")
    print("\nThis file lists every service you use. It is kept outside the working "
          "directory on purpose.")
    return 0


def cmd_worklist(args: argparse.Namespace) -> int:
    import os

    from offlist.cli import render_worklist
    from offlist.sources.breach_hibp import CONSENT_NOTICE, HibpSource
    from offlist.sources.broker_registry import BrokerRegistrySource
    from offlist.sources.public_exposure import PublicExposureSource
    from offlist.sources.probe import ProbeSource
    from offlist.sources.vault_csv import vault_domains
    from offlist.worklist import merge, remediation, store, triage

    if args.explain_hibp:
        print(CONSENT_NOTICE)
        return 0

    email = _resolve_email(args.email)
    hibp_key = args.hibp_key or os.environ.get("OFFLIST_HIBP_KEY")

    ctx = RunContext(
        timeout=args.timeout,
        vault_paths=tuple(args.vault),
        hibp_api_key=hibp_key,
        extras={"include_all_brokers": args.include_all_brokers},
    )

    sources = [BrokerRegistrySource(), PublicExposureSource()]
    if args.vault:
        from offlist.sources.vault_csv import VaultCsvSource

        sources.insert(0, VaultCsvSource())
    if not args.skip_probe:
        sources.append(ProbeSource())
    if hibp_key:
        sources.append(HibpSource())
    else:
        print("(HIBP not queried -- no key. `offlist worklist --explain-hibp` "
              "explains what it would disclose.)\n", file=sys.stderr)

    async def gather():
        found = []
        for source in sources:
            async for ev in source.collect(email, ctx):
                found.append(ev)
        return found

    evidence = asyncio.run(gather())
    domains = vault_domains([Path(p) for p in args.vault]) if args.vault else set()

    records = triage.triage(merge.merge(evidence, vault_domains=domains))
    records = remediation.attach(records, jurisdiction=args.jurisdiction)
    records = store.merge_with_history(email, records)
    records = triage.triage(remediation.attach(records, jurisdiction=args.jurisdiction))
    store.save(email, records)

    renderers = {"term": render_worklist.to_terminal,
                 "md": render_worklist.to_markdown,
                 "json": render_worklist.to_json}
    text = renderers[args.format](records, str(email))
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"worklist written to {args.output}")
    else:
        print(text)
    return 0


def cmd_act(args: argparse.Namespace) -> int:
    from offlist.act import confirm, letters, plan, unsubscribe
    from offlist.act.message import load_messages
    from offlist.act.models import ActionKind, ActionResult
    from offlist.cli import render_act
    from offlist.worklist import store

    if getattr(args, "bulk_consent", False):
        sys.exit(
            "[-] There is no bulk-consent flag, by design.\n"
            "    Each item is shown in full and approved on its own. The point of\n"
            "    the prompt is that a person read the specific request before it\n"
            "    went out; a flag to skip reading removes the only safeguard."
        )

    email = _resolve_email(args.email)
    records = store.load(email)
    if not records:
        sys.exit("[-] No worklist for this address yet. Run `offlist worklist "
                 f"{email}` first.")
    if args.only:
        wanted = set(args.only)
        records = [r for r in records if r.service in wanted]

    messages = load_messages([Path(p) for p in args.mail]) if args.mail else []
    if args.mail:
        signed = sum(1 for m in messages if m.one_click)
        print(f"read {len(messages)} message(s); {signed} advertise one-click unsubscribe\n")

    letters_dir = Path(args.letters_dir)
    actions = plan.build(records, email, messages=messages, letters_dir=letters_dir,
                         jurisdiction=args.jurisdiction, full_name=args.name)

    if not args.execute:
        print(render_act.render(actions, str(email)))
        return 0

    try:
        confirm.require_interactive()
    except confirm.ConsentUnavailable as exc:
        sys.exit(f"[-] {exc}")

    results: list[ActionResult] = []

    # Letters first: writing a file is not an outward action, so it needs no
    # prompt -- but it is reported, and nothing mails it.
    to_write = [a for a in actions if a.kind is ActionKind.WRITE_LETTER]
    for action in to_write:
        record = next(r for r in records if r.service == action.service)
        path = letters.write(record, email, letters_dir,
                             jurisdiction=args.jurisdiction, full_name=args.name)
        results.append(ActionResult(action, "written", f"wrote {path}"))
    if to_write:
        print(f"wrote {len(to_write)} deletion letter(s) to {letters_dir}/ "
              f"-- review and send them yourself; offlist has no mail client.\n")

    def record_results() -> None:
        by_service: dict[str, list] = {}
        for result in results:
            by_service.setdefault(result.action.service, []).append(result.to_record())
        for rec in records:
            if rec.service not in by_service:
                continue
            rec.actions_taken = list(rec.actions_taken) + by_service[rec.service]
            if any(r["outcome"] in ("executed", "written")
                   for r in by_service[rec.service]):
                rec.state = "actioned"
        store.save(email, records)

    sendable = [a for a in actions if a.executable]
    if not sendable:
        record_results()
        print("Nothing is eligible to be sent automatically.")
        print(render_act.render(actions, str(email), executed=True))
        return 0

    async def run_all():
        import httpx

        async with httpx.AsyncClient(timeout=args.timeout,
                                     follow_redirects=True) as client:
            for index, action in enumerate(sendable, start=1):
                if not confirm.ask(action, index, len(sendable)):
                    results.append(ActionResult(action, "declined", "not approved"))
                    print("  skipped.")
                    continue
                outcome = await unsubscribe.execute(action, client=client)
                results.append(outcome)
                print(f"  {outcome.outcome}: {outcome.detail}")

    asyncio.run(run_all())

    record_results()

    print()
    print(render_act.render(actions, str(email), executed=True))
    executed = sum(1 for r in results if r.outcome == "executed")
    declined = sum(1 for r in results if r.outcome == "declined")
    print(f"\n{executed} sent, {declined} declined, "
          f"{len(to_write)} letter(s) written but not sent.")
    return 0


def cmd_brokers(args: argparse.Namespace) -> int:
    from offlist.sources import broker_registry as br

    if args.action == "show":
        rows = br.load_cached()
        print(f"{len(rows)} brokers cached at {br.cache_path()}")
        for row in rows[:20]:
            print(f"  {row['name'][:44]:46s} {row['domain']}")
        if len(rows) > 20:
            print(f"  ... and {len(rows) - 20} more")
        return 0

    url = args.url or br.CA_REGISTRY_URL
    print(f"fetching {url}")
    try:
        rows = asyncio.run(br.fetch_registry(url))
    except Exception as exc:
        print(f"[-] could not fetch the registry: {type(exc).__name__}: {exc}")
        print("    The CPPA publishes registry.csv from "
              "https://cppa.ca.gov/data_broker_registry/ -- download it and pass "
              "--url file:///path/to/registry.csv, or drop it at "
              f"{br.cache_path()}")
        return 1
    path = br.save_cache(rows)
    named = sum(1 for r in rows if r["domain"])
    print(f"cached {len(rows)} registered brokers ({named} with a resolvable domain) -> {path}")
    return 0


def cmd_canary(args: argparse.Namespace) -> int:
    import yaml

    from offlist.catalogue.canary import judge, random_negative, write_ledger
    from offlist.catalogue.loader import load_catalogue
    from offlist.sources.probe import run_probes

    entries = load_catalogue(include_disabled=args.include_disabled)
    if args.only:
        wanted = set(args.only)
        entries = [e for e in entries if e.id in wanted or e.category in wanted]

    positives: dict[str, str] = {}
    if args.positives:
        loaded = yaml.safe_load(Path(args.positives).read_text(encoding="utf-8")) or {}
        positives = loaded.get("sites", loaded)

    ctx = RunContext(timeout=args.timeout, concurrency=args.concurrency,
                     include_disabled=args.include_disabled)

    negative = random_negative()
    print(f"negative control: {negative}")
    neg_results = {r.site_id: r
                   for r in asyncio.run(run_probes(negative, ctx, entries,
                                                   downgrade=False))}

    pos_results: dict[str, object] = {}
    for site_id, address in positives.items():
        entry = next((e for e in entries if e.id == site_id), None)
        if entry is None:
            continue
        got = asyncio.run(run_probes(EmailAddress(address), ctx, [entry],
                                     downgrade=False))
        if got:
            pos_results[site_id] = got[0]

    outcomes = []
    for entry in entries:
        neg = neg_results.get(entry.id)
        if neg is None:
            continue
        outcomes.append(judge(entry, neg, pos_results.get(entry.id)))

    failed = [o for o in outcomes if not o.passed]
    proven = [o for o in outcomes if o.discriminating.value == "yes"]

    print(f"\n{len(outcomes)} entries checked")
    print(f"  {len(outcomes) - len(failed)} passed  |  {len(failed)} failed  "
          f"|  {len(proven)} proven to discriminate")
    if failed:
        print("\nfailures (a negative probe should return exactly `not_registered`):")
        for o in sorted(failed, key=lambda x: x.site_id):
            print(f"  {o.site_id:24s} {o.note}")

    if args.write_ledger:
        path = write_ledger(outcomes)
        print(f"\nledger written to {path}")
    else:
        print("\n(run with --write-ledger to record this)")
    return 1 if failed else 0


def cmd_doctor(args: argparse.Namespace) -> int:
    from offlist.catalogue.loader import load_catalogue

    entries = load_catalogue(include_disabled=True)
    enabled = [e for e in entries if e.enabled]
    declarative = [e for e in entries if e.steps]
    proven = [e for e in entries if e.canary.discriminating.value == "yes"]
    explicit = [e for e in entries if e.negative_is_explicit]

    print(f"catalogue: {len(entries)} sites")
    print(f"  enabled                 {len(enabled)}")
    print(f"  disabled                {len(entries) - len(enabled)}")
    print(f"  declarative             {len(declarative)}")
    print(f"  still on legacy bridge  {len(entries) - len(declarative)}")
    print(f"  proven discriminating   {len(proven)}")
    print(f"  explicit negative rule  {len(explicit)}")
    print()

    if args.by == "category":
        rows = Counter(e.category for e in entries)
        health = {c: sum(1 for e in entries if e.category == c and e.enabled)
                  for c in rows}
        print(f"{'category':18s} {'sites':>6s} {'enabled':>8s} {'rate':>6s}")
        for cat, total in sorted(rows.items(), key=lambda kv: -kv[1]):
            ok = health[cat]
            print(f"{cat:18s} {total:6d} {ok:8d} {100*ok//total:5d}%")
        return 0

    reasons = Counter(e.disabled.status for e in entries
                      if not e.enabled and e.disabled and e.disabled.status)
    print("why sites are disabled (measured, not guessed):")
    ours = {"parse_failed", "endpoint_gone"}
    for reason, count in reasons.most_common():
        note = "  <- stale definition in this repo" if reason in ours else ""
        print(f"  {reason:16s} {count:4d}{note}")
    fixable = sum(c for r, c in reasons.items() if r in ours)
    print(f"\n{fixable} of {sum(reasons.values())} failures are ours to fix.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"scan": cmd_scan, "import": cmd_import, "worklist": cmd_worklist,
                "act": cmd_act, "brokers": cmd_brokers,
                "canary": cmd_canary, "doctor": cmd_doctor}
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
