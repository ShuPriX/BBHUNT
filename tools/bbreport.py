#!/usr/bin/env python3
"""bbreport — scaffold BBHUNT daily/weekly reports from templates + state.

Creates the report skeleton with the statistics block pre-filled from state,
so the run only spends tokens on analysis, not on boilerplate.

  bbreport.py daily                 # reports/daily/YYYY-MM-DD.md
  bbreport.py daily --date 2026-08-16
  bbreport.py weekly                # reports/weekly/YYYY-WXX.md
  bbreport.py new <program> <vuln-id>   # research artifact dir from templates
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(os.environ.get("BBHUNT_ROOT", Path(__file__).resolve().parent.parent))
TEMPLATES = ROOT / "skill" / "templates"
STATE = ROOT / "skill" / "state"


def load_state(name: str) -> dict:
    path = STATE / f"{name}.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        sys.exit(f"bbreport: {path} is corrupt — fix state before reporting")


def render(template: str, values: dict) -> str:
    for key, val in values.items():
        template = template.replace("{{" + key + "}}", str(val))
    return template


def cmd_daily(args: argparse.Namespace) -> None:
    date = args.date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out = ROOT / "reports" / "daily" / f"{date}.md"
    if out.exists() and not args.force:
        sys.exit(f"bbreport: {out.relative_to(ROOT)} exists (use --force to overwrite)")
    current = load_state("current")
    body = render((TEMPLATES / "daily-report.md").read_text(), {
        "DATE": date,
        "RUN": current.get("run_count", 0) + 1,
        "TIMESTAMP": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body)
    print(out.relative_to(ROOT))


def cmd_weekly(args: argparse.Namespace) -> None:
    now = datetime.now(timezone.utc)
    week = args.week or now.strftime("%G-W%V")
    out = ROOT / "reports" / "weekly" / f"{week}.md"
    if out.exists() and not args.force:
        sys.exit(f"bbreport: {out.relative_to(ROOT)} exists (use --force to overwrite)")
    history = load_state("history").get("runs", [])
    cutoff = now - timedelta(days=7)
    recent = []
    for run in history:
        try:
            at = datetime.strptime(run["at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        if at >= cutoff:
            recent.append(run)
    body = render((TEMPLATES / "weekly-report.md").read_text(), {
        "WEEK": week,
        "RANGE": f"{cutoff.strftime('%Y-%m-%d')} → {now.strftime('%Y-%m-%d')}",
        "RUNS": len(recent),
    })
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body)
    print(out.relative_to(ROOT))


def cmd_new(args: argparse.Namespace) -> None:
    year = args.year or datetime.now(timezone.utc).strftime("%Y")
    out = ROOT / "research" / year / args.program / args.vuln_id
    if out.exists() and not args.force:
        sys.exit(f"bbreport: {out.relative_to(ROOT)} exists (use --force to overwrite)")
    out.mkdir(parents=True, exist_ok=True)
    for name in ("README.md", "report.md", "poc.md", "metadata.json", "nuclei.yaml"):
        src = TEMPLATES / name
        if src.exists():
            shutil.copy(src, out / name)
    (out / "changes.diff").touch()
    print(out.relative_to(ROOT))
    print("  templates copied — fill every placeholder, then:")
    print(f"  python3 tools/bbstate.py validate {out.relative_to(ROOT)}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="bbreport", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("daily"); p.set_defaults(fn=cmd_daily)
    p.add_argument("--date"); p.add_argument("--force", action="store_true")

    p = sub.add_parser("weekly"); p.set_defaults(fn=cmd_weekly)
    p.add_argument("--week"); p.add_argument("--force", action="store_true")

    p = sub.add_parser("new"); p.set_defaults(fn=cmd_new)
    p.add_argument("program"); p.add_argument("vuln_id")
    p.add_argument("--year"); p.add_argument("--force", action="store_true")

    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
