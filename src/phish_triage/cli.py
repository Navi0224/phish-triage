"""Command-line interface.

    phish-triage analyze suspicious.eml
    phish-triage analyze suspicious.eml --out-dir reports --report-format html
    phish-triage analyze samples/                 # batch: every .eml in the folder
    phish-triage analyze suspicious.eml --json    # JSON to stdout, for SOAR/SIEM pipelines
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .analyzer import analyze_file
from .config import load_config
from .models import TriageResult
from .report import to_console, to_html, to_json, to_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phish-triage",
        description="Triage a suspicious email (.eml) and produce an analyst-ready verdict. "
                    "URLs are never opened and attachments are never executed.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    an = sub.add_parser("analyze", help="analyse an .eml file or every .eml file in a folder")
    an.add_argument("path", type=Path, help=".eml file or folder of .eml files")
    an.add_argument("--config", type=Path, help="JSON config overriding weights/thresholds/brands")
    an.add_argument("--json", action="store_true", help="print JSON to stdout instead of the console summary")
    an.add_argument("--out-dir", type=Path, help="write <name>.json and a report for each email to this folder")
    an.add_argument("--report-format", choices=["md", "html", "both"], default="md",
                    help="report format written to --out-dir (default: md)")
    an.add_argument("--enrich", action="store_true",
                    help="look up hashes/URLs on VirusTotal/URLhaus (needs VT_API_KEY / URLHAUS_AUTH_KEY env vars)")
    an.add_argument("-q", "--quiet", action="store_true", help="batch mode: only print the summary table")
    return parser


def collect_files(path: Path) -> list[Path]:
    """A single file, or every *.eml file (sorted) directly inside a folder."""
    if path.is_dir():
        return sorted(p for p in path.iterdir() if p.is_file() and p.suffix.lower() == ".eml")
    return [path]


def write_outputs(result: TriageResult, source: Path, out_dir: Path, report_format: str) -> list[Path]:
    """Write JSON + report files. Names come from the .eml file name, not from email content."""
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = source.stem
    written = [out_dir / f"{stem}.json"]
    written[0].write_text(to_json(result), encoding="utf-8")
    if report_format in ("md", "both"):
        written.append(out_dir / f"{stem}.md")
        written[-1].write_text(to_markdown(result), encoding="utf-8")
    if report_format in ("html", "both"):
        written.append(out_dir / f"{stem}.html")
        written[-1].write_text(to_html(result), encoding="utf-8")
    return written


def summary_table(results: list[TriageResult]) -> str:
    lines = [f"{'VERDICT':<14} {'SCORE':>5}  FILE", "-" * 60]
    lines += [f"{r.verdict:<14} {r.score:>5}  {Path(r.file).name}" for r in results]
    return "\n".join(lines)


def cmd_analyze(args: argparse.Namespace) -> int:
    if not args.path.exists():
        print(f"error: {args.path} does not exist", file=sys.stderr)
        return 1
    files = collect_files(args.path)
    if not files:
        print(f"error: no .eml files found in {args.path}", file=sys.stderr)
        return 1
    config = load_config(args.config)
    batch = args.path.is_dir()

    results: list[TriageResult] = []
    for file in files:
        try:
            result = analyze_file(file, config=config, do_enrich=args.enrich)
        except OSError as exc:
            print(f"error: could not read {file}: {exc}", file=sys.stderr)
            continue
        results.append(result)
        if args.out_dir:
            for written in write_outputs(result, file, args.out_dir, args.report_format):
                print(f"wrote {written}", file=sys.stderr)
        if not args.json and not (batch and args.quiet):
            print(to_console(result))

    if args.json:
        payload = [json.loads(to_json(r)) for r in results]
        print(json.dumps(payload if batch else payload[0], indent=2, ensure_ascii=True))
    elif batch:
        print(summary_table(results))
    return 0 if results else 1


def main(argv: Sequence[str] | None = None) -> int:
    # Email content can contain any Unicode. On a Windows console (cp1252) that
    # would raise UnicodeEncodeError, so replace unprintable characters instead.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        return cmd_analyze(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
