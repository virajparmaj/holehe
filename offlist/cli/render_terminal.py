"""Terminal output.

Results are grouped by status rather than printed as one flat list, because the
point of the status enum is that the groups mean different things: one is a
finding, one needs a retry, one needs a client change, and one is a bug report
against this repo.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Sequence

from offlist.core.models import ProbeResult, Status

GLYPH = {
    Status.REGISTERED: ("[+]", "green", "account found"),
    Status.NOT_REGISTERED: ("[-]", "magenta", "no account"),
    Status.INDETERMINATE: ("[?]", "cyan", "no answer -- site never proven to discriminate"),
    Status.RATE_LIMITED: ("[x]", "yellow", "rate limited -- retry later"),
    Status.BLOCKED: ("[#]", "yellow", "blocked by bot protection -- needs a different client"),
    Status.ENDPOINT_GONE: ("[404]", "red", "endpoint gone -- the definition is stale"),
    Status.UNREACHABLE: ("[!]", "red", "unreachable -- host may be dead"),
    Status.SERVER_ERROR: ("[5xx]", "red", "server error on their side"),
    Status.PARSE_FAILED: ("[~]", "red", "unrecognised response -- the definition is stale"),
    Status.DISABLED: ("[.]", "white", "disabled in the catalogue"),
    Status.SKIPPED: ("[.]", "white", "skipped -- needs an explicit consent flag"),
}

ORDER = [
    Status.REGISTERED, Status.INDETERMINATE, Status.NOT_REGISTERED,
    Status.RATE_LIMITED, Status.BLOCKED, Status.SERVER_ERROR,
    Status.ENDPOINT_GONE, Status.PARSE_FAILED, Status.UNREACHABLE,
    Status.SKIPPED, Status.DISABLED,
]


def _paint(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    try:
        from termcolor import colored

        return colored(text, color)
    except ImportError:
        return text


def render(results: Sequence[ProbeResult], email: str, elapsed: float, *,
           color: bool = True, only_found: bool = False, verbose: bool = False) -> str:
    lines: list[str] = []
    bar = "*" * (len(email) + 6)
    lines += [bar, f"   {email}", bar, ""]

    grouped: dict[Status, list[ProbeResult]] = defaultdict(list)
    for r in results:
        grouped[r.status].append(r)

    for status in ORDER:
        rows = grouped.get(status)
        if not rows:
            continue
        if only_found and status is not Status.REGISTERED:
            continue
        if status is Status.DISABLED and not verbose:
            continue

        glyph, color_name, blurb = GLYPH[status]
        lines.append(_paint(f"{blurb}  ({len(rows)})", color_name, color))
        for r in sorted(rows, key=lambda x: x.domain):
            suffix = ""
            if r.emailrecovery:
                suffix += f"  recovery-email {r.emailrecovery}"
            if r.phone_number:
                suffix += f"  recovery-phone {r.phone_number}"
            if r.full_name:
                suffix += f"  name {r.full_name}"
            if r.created_at:
                suffix += f"  created {r.created_at}"
            if verbose and r.detail:
                suffix += f"   ({r.detail})"
            lines.append(_paint(f"  {glyph} {r.domain}{suffix}", color_name, color))
        lines.append("")

    counts = Counter(r.status for r in results)
    answered = counts[Status.REGISTERED] + counts[Status.NOT_REGISTERED]
    proven = sum(1 for r in results
                 if r.status.is_answer and r.discriminating.value == "yes")
    failed = sum(v for k, v in counts.items() if k.is_failure)
    stale = sum(v for k, v in counts.items() if k.is_actionable_by_us)

    lines.append(f"{len(results)} sites checked in {elapsed:.1f}s")
    lines.append(
        f"  {answered} answered ({proven} from sites proven to discriminate) "
        f"| {counts[Status.INDETERMINATE]} indeterminate | {failed} failed"
    )
    if stale:
        lines.append(
            f"  {stale} failures are stale definitions in this repo, not their fault "
            f"-- run `offlist doctor` for the breakdown"
        )
    return "\n".join(lines)
