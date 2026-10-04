"""Run the isolated useful agent, approvals, attack, profile reload and budget showcase."""
import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo.judge_showcase import run_showcase  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semantic", choices=["deberta", "fixture"], default="deberta",
        help="Real pinned DeBERTa by default; fixture is explicitly for fast enforcement checks")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/judge-showcase.json")
    args = parser.parse_args()
    report = asyncio.run(run_showcase(args.semantic))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for case in report["cases"]:
        print(f"PASS {case['case']}", flush=True)
    print(f"{report['passed']} scenarios passed with {args.semantic}; evidence: {args.output}")


if __name__ == "__main__":
    main()
