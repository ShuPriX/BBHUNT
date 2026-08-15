#!/usr/bin/env python3
"""bbscore — reproducible BBHUNT scoring.

Weights come from config/scoring.yaml so a score can be recomputed and audited
later. Each sub-score is given out of its own weight cap, not out of 100.

  bbscore.py program --reward 20 --acceptance 15 --scope 12 --surface 11 \
                     --activity 8 --dupres 7 --feasibility 4
  bbscore.py opportunity --impact 27 --payout 16 --acceptance 11 \
                         --exploitability 13 --scope 8 --freshness 4 --dupres 4
  bbscore.py confidence --items 4 --score 72
  bbscore.py weights
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config" / "scoring.yaml"

PROGRAM_FIELDS = [
    ("reward", "reward_potential"),
    ("acceptance", "acceptance_evidence"),
    ("scope", "scope_quality"),
    ("surface", "attack_surface"),
    ("activity", "program_activity"),
    ("dupres", "duplicate_resistance"),
    ("feasibility", "research_feasibility"),
]

OPPORTUNITY_FIELDS = [
    ("impact", "technical_impact"),
    ("payout", "payout_potential"),
    ("acceptance", "acceptance_evidence"),
    ("exploitability", "exploitability"),
    ("scope", "scope_quality"),
    ("freshness", "freshness"),
    ("dupres", "duplicate_resistance"),
]


def load_config() -> dict:
    try:
        import yaml
    except ImportError:
        sys.exit("bbscore: pyyaml required (pip install pyyaml)")
    if not CONFIG.exists():
        sys.exit(f"bbscore: missing {CONFIG}")
    with CONFIG.open() as fh:
        return yaml.safe_load(fh)


def score(model_weights: dict, fields: list, args: argparse.Namespace) -> dict:
    total = 0.0
    breakdown = {}
    errors = []
    for flag, key in fields:
        cap = model_weights[key]
        value = getattr(args, flag)
        if value is None:
            errors.append(f"--{flag} is required (0-{cap})")
            continue
        if value < 0 or value > cap:
            errors.append(f"--{flag}={value} out of range for {key} (0-{cap})")
            continue
        breakdown[key] = {"score": value, "max": cap}
        total += value
    if errors:
        sys.exit("bbscore: " + "; ".join(errors))
    return {"total": round(total, 1), "max": sum(model_weights.values()), "breakdown": breakdown}


def band(cfg: dict, value: float, items: int) -> str:
    bands = cfg["confidence_bands"]
    if items < bands["min_evidence_items"]:
        return "INSUFFICIENT DATA"
    for name in ("VERY_HIGH", "HIGH", "MEDIUM", "LOW"):
        if value >= bands[name]:
            return name.replace("_", " ")
    return "INSUFFICIENT DATA"


def verdict(cfg: dict, total: float, model: str) -> str:
    t = cfg["thresholds"]
    if model == "program_opportunity_score":
        if total >= t["strong_evidence"]:
            return "STRONG EVIDENCE — top-tier program (ranking tier, not a payout probability)"
        if total >= t["research_worthy"]:
            return "WORTH HUNTING"
        return "BELOW BAR — do not spend deep analysis"
    if total >= t["strong_evidence"]:
        return "STRONG EVIDENCE — lead with this one"
    if total >= t["report_worthy"]:
        return "REPORT WORTHY"
    if total >= t["research_worthy"]:
        return "RESEARCH WORTHY — keep as RESEARCH CANDIDATE"
    return "BELOW BAR — do not spend deep analysis"


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(prog="bbscore", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_prog = sub.add_parser("program", help="PROGRAM OPPORTUNITY SCORE")
    for flag, key in PROGRAM_FIELDS:
        p_prog.add_argument(f"--{flag}", type=float,
                            help=f"{key} (0-{cfg['program_opportunity_score'][key]})")

    p_opp = sub.add_parser("opportunity", help="OPPORTUNITY SCORE (vuln x program)")
    for flag, key in OPPORTUNITY_FIELDS:
        p_opp.add_argument(f"--{flag}", type=float,
                           help=f"{key} (0-{cfg['opportunity_score'][key]})")

    p_conf = sub.add_parser("confidence", help="band a payout/acceptance confidence score")
    p_conf.add_argument("--score", type=float, required=True)
    p_conf.add_argument("--items", type=int, required=True,
                        help="number of independent evidence items")

    sub.add_parser("weights", help="print the configured weights")

    args = parser.parse_args()

    if args.cmd == "weights":
        print(json.dumps({k: cfg[k] for k in
                          ("program_opportunity_score", "opportunity_score",
                           "thresholds", "confidence_bands")}, indent=2))
        return

    if args.cmd == "confidence":
        result = band(cfg, args.score, args.items)
        print(json.dumps({"score": args.score, "evidence_items": args.items,
                          "band": result}, indent=2))
        return

    model = "program_opportunity_score" if args.cmd == "program" else "opportunity_score"
    fields = PROGRAM_FIELDS if args.cmd == "program" else OPPORTUNITY_FIELDS
    result = score(cfg[model], fields, args)
    result["model"] = model
    result["verdict"] = verdict(cfg, result["total"], model)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
