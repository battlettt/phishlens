"""Render reports as plain text. Every report passes through a final defang step."""

from __future__ import annotations

import textwrap

from . import domains
from .defang import defang_email, defang_text
from .headers import HeaderReport
from .urls import UrlReport
from .verdict import Verdict

WIDTH = 78
FOOTER = ("PhishLens only read the text you pasted. It did not open any links, contact any "
          "server, look up any domain, or save anything.")


def _wrap(text: str, indent: str, first: str | None = None) -> list[str]:
    return textwrap.wrap(text, WIDTH, initial_indent=first if first is not None else indent,
                         subsequent_indent=indent, break_long_words=True, break_on_hyphens=False)


def _title(text: str) -> list[str]:
    return [text, "=" * len(text)]


def _verdict_lines(verdict: Verdict) -> list[str]:
    return [f"VERDICT: {verdict.level}", *_wrap(verdict.summary, "")]


def _reasons(verdict: Verdict, heading: str = "Why (most serious first):") -> list[str]:
    lines = ["", heading]
    if not verdict.reasons:
        lines.append("  No warning signs found.")
    for n, f in enumerate(verdict.reasons, 1):
        prefix = f"  {n}. "
        indent = " " * len(prefix)
        lines += _wrap(f"[{f.severity.upper()}] {f.title}", indent, prefix)
        lines += _wrap(f.detail, indent)
    return lines


def _notes(verdict: Verdict) -> list[str]:
    if not verdict.notes:
        return []
    lines = ["", "Also noted (not counted as warning signs):"]
    for f in verdict.notes:
        lines += _wrap(f"{f.title}. {f.detail}", "    ", "  - ")
    return lines


def _advice(verdict: Verdict) -> list[str]:
    lines = ["", "What to do:"]
    for tip in verdict.advice:
        lines += _wrap(tip, "    ", "  - ")
    return lines


def render_header_report(report: HeaderReport) -> str:
    v = report.verdict
    lines = _title("PhishLens: email header analysis") + [""] + _verdict_lines(v)

    lines += ["", "Sender details (as pasted):"]
    sender = report.from_addr
    if sender:
        shown = (f'"{sender.display}" <{defang_email(sender.address)}>' if sender.display
                 else defang_email(sender.address))
        lines.append(f"  From:         {shown}")
    for reply in report.reply_to:
        lines.append(f"  Reply-To:     {defang_email(reply.address)}")
    if report.return_path:
        lines.append(f"  Return-Path:  {defang_email(report.return_path)}")
    if report.message_id:
        lines.append(f"  Message-ID:   {defang_email(report.message_id)}")
    hop = report.first_hop
    if hop:
        name = hop.helo or hop.ip or "unknown"
        extra = [f"network name {hop.rdns}"] if hop.rdns and hop.rdns != hop.helo else []
        if hop.ip and hop.ip != name:
            extra.append(f"IP {hop.ip}")
        lines.append(f"  First server: {name}" + (f" ({', '.join(extra)})" if extra else ""))
    lines.append(f"  Servers seen: {len(report.hops)} Received line(s)")
    if report.subject:
        lines += _wrap(report.subject, "                ", "  Subject:      ")

    lines += ["", "Authentication checks (from the pasted Authentication-Results):"]
    for name in ("SPF", "DKIM", "DMARC"):
        check = report.auth[name]
        lines.append(f"  {name + ':':<7}{check.status}")
        lines += _wrap(check.explanation, "         ")

    lines += _reasons(v)
    if report.links:
        lines += ["", f"Links found in the message ({len(report.links)}):"]
        for n, link in enumerate(report.links, 1):
            lines += _link_block(link, n)
    lines += _notes(v) + _advice(v) + [""] + _wrap(FOOTER, "")
    return defang_text("\n".join(lines))


def _link_block(link: UrlReport, n: int) -> list[str]:
    lines = _wrap(link.defanged, "     ", f"  {n}. ")
    if link.display_text:
        lines += _wrap(f'Shown as: "{link.display_text}"', "     ")
    lines.append(f"     Link verdict: {link.verdict.level}")
    for f in link.verdict.reasons:
        lines += _wrap(f.title, "         ", f"       - [{f.severity.upper()}] ")
    return lines


def render_url_report(link: UrlReport) -> str:
    v = link.verdict
    lines = _title("PhishLens: link analysis") + [""]
    lines += _wrap(link.defanged, "              ", "Link:         ")
    if link.host:
        ascii_host = domains.to_ascii(link.host)
        unicode_host = domains.to_unicode(link.host)
        site = ascii_host if ascii_host == unicode_host else f"{ascii_host} (displays as {unicode_host})"
        lines += _wrap(site, "              ", "Real site:    ")
    if link.display_text:
        lines += _wrap(f'"{link.display_text}"', "              ", "Shown as:     ")
    lines += [""] + _verdict_lines(v) + _reasons(v) + _notes(v) + _advice(v)
    lines += [""] + _wrap(FOOTER, "")
    return defang_text("\n".join(lines))
