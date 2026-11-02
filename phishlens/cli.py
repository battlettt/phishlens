"""Command-line interface. Reads pasted text, prints a report, stores nothing."""

from __future__ import annotations

import argparse
import sys

from .headers import NotHeadersError, analyze_headers
from .report import render_header_report, render_url_report
from .samples import SAMPLES
from .urls import analyze_text

MAX_INPUT_CHARS = 5_000_000


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishlens",
        description="Analyze pasted email headers or URLs and get a plain-English verdict. "
                    "Nothing is fetched, sent, or stored.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--headers", nargs="?", const="-", metavar="FILE",
                      help="file containing pasted email headers (and optional body); "
                           "use '-' or omit FILE to read from stdin")
    mode.add_argument("--url", nargs="+", metavar="URL",
                      help="one or more URLs, or pasted HTML links such as "
                           "'<a href=\"...\">text</a>'; use '-' to read from stdin")
    mode.add_argument("--demo", action="store_true",
                      help="show a built-in phishing sample and a legitimate sample")
    return parser


def _read(source: str, stdin) -> str:
    if source == "-":
        text = stdin.read(MAX_INPUT_CHARS + 1)
    else:
        with open(source, encoding="utf-8", errors="replace") as handle:
            text = handle.read(MAX_INPUT_CHARS + 1)
    if len(text) > MAX_INPUT_CHARS:
        raise ValueError("input is larger than 5 MB; paste only the headers and message text")
    return text


def run_headers(text: str) -> str:
    return render_header_report(analyze_headers(text))


def run_urls(items: list[str]) -> str:
    reports = [r for item in items for r in analyze_text(item)]
    if not reports:
        raise ValueError("no URL was given")
    return "\n\n".join(render_url_report(r) for r in reports)


def run_demo() -> str:
    parts = ["PhishLens demo: two built-in SAMPLE emails, analyzed exactly like pasted headers."]
    for label, text in SAMPLES:
        parts += ["", "#" * 78, f"# {label}", "#" * 78, "", run_headers(text)]
    return "\n".join(parts)


def main(argv: list[str] | None = None, stdin=None, stdout=None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    parser = build_parser()
    args = parser.parse_args(argv)
    if hasattr(stdout, "reconfigure"):
        stdout.reconfigure(errors="replace")
    try:
        if args.demo:
            output = run_demo()
        elif args.url:
            items = [_read("-", stdin) if u == "-" else u for u in args.url]
            output = run_urls(items)
        elif args.headers is not None:
            output = run_headers(_read(args.headers, stdin))
        elif not stdin.isatty() and (piped := _read("-", stdin)).strip():
            output = run_headers(piped)
        else:
            parser.print_help(stdout)
            return 2
    except NotHeadersError as err:
        print(f"phishlens: {err} To check a single link, use --url.", file=sys.stderr)
        return 2
    except (OSError, ValueError) as err:
        print(f"phishlens: {err}", file=sys.stderr)
        return 2
    print(output, file=stdout)
    return 0
