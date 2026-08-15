#!/usr/bin/env python3
"""bbstate — BBHUNT repository-backed state.

State is how a run stays cheap: it answers "have I already processed this?"
without re-reading old reports. Every run starts with `status` and ends with
`record-run`.

  bbstate.py status
  bbstate.py seen vuln CVE-2026-1234
  bbstate.py seen program acme-h1
  bbstate.py record-program acme-h1 --platform hackerone --score 84 \
             --status active --scope-hash abc123 --payout-max 10000
  bbstate.py record-vuln CVE-2026-1234 --status researched --score 91 \
             --program acme-h1 --path research/2026/acme/CVE-2026-1234
  bbstate.py reject CVE-2026-9999 --reason "excluded class: self-XSS"
  bbstate.py queue --add CVE-2026-5555 --note "awaiting vendor patch"
  bbstate.py fail-source nvd --error "429 rate limited"
  bbstate.py record-run --evaluated 42 --researched 2 --artifacts 6
  bbstate.py stale --days 1
  bbstate.py validate research/2026/acme/CVE-2026-1234
  bbstate.py stats
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get("BBHUNT_ROOT", Path(__file__).resolve().parent.parent))
STATE = ROOT / "skill" / "state"

FILES = {
    "current": STATE / "current.json",
    "programs": STATE / "programs.json",
    "vulnerabilities": STATE / "vulnerabilities.json",
    "history": STATE / "history.json",
}

DEFAULTS = {
    "current": {"last_run": None, "run_count": 0, "phase": "idle",
                "pending_research": [], "failed_sources": [], "notes": ""},
    "programs": {"programs": {}},
    "vulnerabilities": {"vulnerabilities": {}},
    "history": {"runs": []},
}

REQUIRED_ARTIFACTS = ["README.md", "report.md", "poc.md", "metadata.json"]
REQUIRED_METADATA = ["candidate", "program", "severity", "vulnerability_class",
                     "duplicate_risk", "research_confidence", "source_urls", "verified_at"]

# Unfilled template markers. HTML/payload tags that legitimately appear in a
# report or PoC are allowlisted so real evidence is not mistaken for a stub.
HTML_OK = (r"a|b|br|code|em|i|p|pre|q|s|u|strong|span|div|img|svg|iframe|body|form|"
           r"input|button|table|thead|tbody|tr|td|th|h[1-6]|ul|ol|li|hr|script|style|"
           r"details|summary|marquee|object|embed|link|meta|base|video|audio|source")
PLACEHOLDER_RE = re.compile(
    r"\{\{[^}]+\}\}"                                     # {{DATE}} style
    r"|<(?!/?(?:" + HTML_OK + r")\b)[A-Za-z][^<>\n]{1,60}>"  # <Product>, <one sentence: ...>
    r"|\b(?:TODO|FIXME|PLACEHOLDER|FILL ME|XXX)\b"
)


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load(name: str) -> dict:
    path = FILES[name]
    if not path.exists():
        return json.loads(json.dumps(DEFAULTS[name]))
    try:
        with path.open() as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        sys.exit(f"bbstate: {path} is corrupt ({exc}). Fix or delete it; do not guess state.")


def save(name: str, data: dict) -> None:
    path = FILES[name]
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    with tmp.open("w") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    tmp.replace(path)


def days_since(stamp: str | None) -> float | None:
    if not stamp:
        return None
    try:
        then = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - then).total_seconds() / 86400


# ── commands ────────────────────────────────────────────────────────

def cmd_init(_: argparse.Namespace) -> None:
    for name in FILES:
        if not FILES[name].exists():
            save(name, DEFAULTS[name])
            print(f"created {FILES[name].relative_to(ROOT)}")
        else:
            print(f"exists  {FILES[name].relative_to(ROOT)}")


def cmd_status(_: argparse.Namespace) -> None:
    cur = load("current")
    progs = load("programs")["programs"]
    vulns = load("vulnerabilities")["vulnerabilities"]
    age = days_since(cur.get("last_run"))
    by_status: dict[str, int] = {}
    for v in vulns.values():
        by_status[v.get("status", "unknown")] = by_status.get(v.get("status", "unknown"), 0) + 1
    out = {
        "last_run": cur.get("last_run"),
        "days_since_last_run": round(age, 2) if age is not None else None,
        "run_count": cur.get("run_count", 0),
        "phase": cur.get("phase"),
        "programs_tracked": len(progs),
        "programs_active": sum(1 for p in progs.values() if p.get("status") == "active"),
        "programs_high_value": sum(1 for p in progs.values() if (p.get("score") or 0) >= 80),
        "vulns_tracked": len(vulns),
        "vulns_by_status": by_status,
        "pending_research": cur.get("pending_research", []),
        "failed_sources": cur.get("failed_sources", []),
    }
    print(json.dumps(out, indent=2))


def cmd_seen(args: argparse.Namespace) -> None:
    if args.kind == "vuln":
        record = load("vulnerabilities")["vulnerabilities"].get(args.id)
    else:
        record = load("programs")["programs"].get(args.id)
    if not record:
        print("NEW")
        sys.exit(0)
    age = days_since(record.get("updated_at"))
    extra = f" age={age:.1f}d" if age is not None else ""
    print(f"SEEN:{record.get('status', 'unknown')}{extra}")
    if args.verbose:
        print(json.dumps(record, indent=2))
    # exit 1 signals "already processed" so shell callers can skip cheaply
    sys.exit(1)


def cmd_record_program(args: argparse.Namespace) -> None:
    data = load("programs")
    existing = data["programs"].get(args.id, {})
    changed = existing.get("scope_hash") not in (None, args.scope_hash) if args.scope_hash else False
    record = {
        **existing,
        "program_id": args.id,
        "platform": args.platform or existing.get("platform"),
        "status": args.status or existing.get("status", "unknown"),
        "score": args.score if args.score is not None else existing.get("score"),
        "scope_hash": args.scope_hash or existing.get("scope_hash"),
        "payout_min": args.payout_min if args.payout_min is not None else existing.get("payout_min"),
        "payout_max": args.payout_max if args.payout_max is not None else existing.get("payout_max"),
        "url": args.url or existing.get("url"),
        "updated_at": now(),
        "first_seen": existing.get("first_seen", now()),
        "scope_changed_at": now() if changed else existing.get("scope_changed_at"),
    }
    data["programs"][args.id] = record
    save("programs", data)
    print(f"recorded program {args.id}" + (" (SCOPE CHANGED)" if changed else ""))


def cmd_record_vuln(args: argparse.Namespace) -> None:
    data = load("vulnerabilities")
    existing = data["vulnerabilities"].get(args.id, {})
    record = {
        **existing,
        "id": args.id,
        "status": args.status,
        "score": args.score if args.score is not None else existing.get("score"),
        "program": args.program or existing.get("program"),
        "product": args.product or existing.get("product"),
        "path": args.path or existing.get("path"),
        "duplicate_risk": args.duplicate_risk or existing.get("duplicate_risk"),
        "source_fingerprint": args.fingerprint or existing.get("source_fingerprint"),
        "updated_at": now(),
        "first_seen": existing.get("first_seen", now()),
    }
    data["vulnerabilities"][args.id] = record
    save("vulnerabilities", data)
    print(f"recorded vuln {args.id} status={args.status}")


def cmd_reject(args: argparse.Namespace) -> None:
    data = load("vulnerabilities")
    existing = data["vulnerabilities"].get(args.id, {})
    data["vulnerabilities"][args.id] = {
        **existing,
        "id": args.id,
        "status": "rejected",
        "reject_reason": args.reason,
        "reject_evidence": args.evidence,
        "updated_at": now(),
        "first_seen": existing.get("first_seen", now()),
    }
    save("vulnerabilities", data)
    print(f"rejected {args.id}: {args.reason}")


def cmd_queue(args: argparse.Namespace) -> None:
    cur = load("current")
    queue = cur.get("pending_research", [])
    if args.add:
        if not any(q.get("id") == args.add for q in queue):
            queue.append({"id": args.add, "note": args.note or "", "added_at": now()})
    if args.remove:
        queue = [q for q in queue if q.get("id") != args.remove]
    cur["pending_research"] = queue
    save("current", cur)
    print(json.dumps(queue, indent=2))


def cmd_fail_source(args: argparse.Namespace) -> None:
    cur = load("current")
    fails = [f for f in cur.get("failed_sources", []) if f.get("source") != args.source]
    fails.append({"source": args.source, "error": args.error, "at": now()})
    cur["failed_sources"] = fails
    save("current", cur)
    print(f"recorded source failure: {args.source}")


def cmd_record_run(args: argparse.Namespace) -> None:
    cur = load("current")
    entry = {
        "run": cur.get("run_count", 0) + 1,
        "at": now(),
        "programs_evaluated": args.evaluated,
        "candidates_researched": args.researched,
        "candidates_rejected": args.rejected,
        "artifacts_generated": args.artifacts,
        "top_opportunity": args.top,
        "next_priority": args.next,
        "failed_sources": [f["source"] for f in cur.get("failed_sources", [])],
    }
    hist = load("history")
    hist["runs"].append(entry)
    save("history", hist)

    cur["last_run"] = entry["at"]
    cur["run_count"] = entry["run"]
    cur["phase"] = "idle"
    cur["failed_sources"] = []          # cleared each run; history keeps the record
    save("current", cur)
    print(json.dumps(entry, indent=2))


def cmd_stale(args: argparse.Namespace) -> None:
    """Programs whose verification is older than --days (candidates for re-check)."""
    progs = load("programs")["programs"]
    stale = []
    for pid, p in progs.items():
        age = days_since(p.get("updated_at"))
        if age is None or age >= args.days:
            stale.append({"program_id": pid, "age_days": round(age, 2) if age else None,
                          "score": p.get("score"), "status": p.get("status")})
    stale.sort(key=lambda x: (x["score"] or 0), reverse=True)
    print(json.dumps(stale, indent=2))


def cmd_validate(args: argparse.Namespace) -> None:
    path = Path(args.path)
    if not path.is_absolute():
        path = ROOT / path
    problems = []
    if not path.is_dir():
        sys.exit(f"bbstate: not a directory: {path}")
    for artifact in REQUIRED_ARTIFACTS:
        target = path / artifact
        if not target.exists():
            problems.append(f"missing {artifact}")
        elif target.stat().st_size == 0:
            problems.append(f"empty {artifact}")
    meta_path = path / "metadata.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
            for field in REQUIRED_METADATA:
                if field not in meta:
                    problems.append(f"metadata.json missing '{field}'")
                elif meta[field] in ("", []):
                    problems.append(f"metadata.json '{field}' is empty")
            if meta.get("source_urls") == []:
                problems.append("metadata.json has no source_urls — every claim needs a citation")
        except json.JSONDecodeError as exc:
            problems.append(f"metadata.json invalid JSON: {exc}")
    # placeholder sweep — an unfilled template must never ship as a finding
    for artifact in REQUIRED_ARTIFACTS + ["nuclei.yaml"]:
        target = path / artifact
        if not target.exists():
            continue
        found = PLACEHOLDER_RE.findall(target.read_text(errors="ignore"))
        markers = []
        for match in found:
            marker = match if isinstance(match, str) else match[0]
            if marker and marker not in markers:
                markers.append(marker)
        if markers:
            shown = ", ".join(repr(m) for m in markers[:3])
            more = f" (+{len(markers) - 3} more)" if len(markers) > 3 else ""
            problems.append(f"{artifact} has unfilled placeholders: {shown}{more}")
    if problems:
        print("FAIL")
        for p in problems:
            print(f"  - {p}")
        sys.exit(1)
    print("OK — artifact set complete")


def cmd_stats(_: argparse.Namespace) -> None:
    hist = load("history")["runs"]
    vulns = load("vulnerabilities")["vulnerabilities"]
    progs = load("programs")["programs"]
    researched = sum(1 for v in vulns.values() if v.get("status") == "researched")
    rejected = sum(1 for v in vulns.values() if v.get("status") == "rejected")
    print(json.dumps({
        "runs": len(hist),
        "first_run": hist[0]["at"] if hist else None,
        "last_run": hist[-1]["at"] if hist else None,
        "programs_tracked": len(progs),
        "vulns_tracked": len(vulns),
        "researched": researched,
        "rejected": rejected,
        "reject_rate": round(rejected / len(vulns), 3) if vulns else None,
        "total_artifacts": sum(r.get("artifacts_generated") or 0 for r in hist),
    }, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(prog="bbstate", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init").set_defaults(fn=cmd_init)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("stats").set_defaults(fn=cmd_stats)

    p = sub.add_parser("seen"); p.set_defaults(fn=cmd_seen)
    p.add_argument("kind", choices=["vuln", "program"])
    p.add_argument("id")
    p.add_argument("-v", "--verbose", action="store_true")

    p = sub.add_parser("record-program"); p.set_defaults(fn=cmd_record_program)
    p.add_argument("id")
    p.add_argument("--platform"); p.add_argument("--status")
    p.add_argument("--score", type=float); p.add_argument("--scope-hash")
    p.add_argument("--payout-min", type=float); p.add_argument("--payout-max", type=float)
    p.add_argument("--url")

    p = sub.add_parser("record-vuln"); p.set_defaults(fn=cmd_record_vuln)
    p.add_argument("id")
    p.add_argument("--status", required=True,
                   choices=["candidate", "researching", "researched", "reported",
                            "unreproduced", "insufficient-evidence", "rejected"])
    p.add_argument("--score", type=float); p.add_argument("--program")
    p.add_argument("--product"); p.add_argument("--path")
    p.add_argument("--duplicate-risk")
    p.add_argument("--fingerprint", help="hash of the source/patch state that was analyzed")

    p = sub.add_parser("reject"); p.set_defaults(fn=cmd_reject)
    p.add_argument("id"); p.add_argument("--reason", required=True)
    p.add_argument("--evidence", default="")

    p = sub.add_parser("queue"); p.set_defaults(fn=cmd_queue)
    p.add_argument("--add"); p.add_argument("--remove"); p.add_argument("--note")

    p = sub.add_parser("fail-source"); p.set_defaults(fn=cmd_fail_source)
    p.add_argument("source"); p.add_argument("--error", default="")

    p = sub.add_parser("record-run"); p.set_defaults(fn=cmd_record_run)
    p.add_argument("--evaluated", type=int, default=0)
    p.add_argument("--researched", type=int, default=0)
    p.add_argument("--rejected", type=int, default=0)
    p.add_argument("--artifacts", type=int, default=0)
    p.add_argument("--top", default=""); p.add_argument("--next", default="")

    p = sub.add_parser("stale"); p.set_defaults(fn=cmd_stale)
    p.add_argument("--days", type=float, default=7.0)

    p = sub.add_parser("validate"); p.set_defaults(fn=cmd_validate)
    p.add_argument("path")

    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
