"""Make URLs, domains, and addresses non-clickable before they are shown."""

from __future__ import annotations

import re

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
_DEFANGED_SCHEMES = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "ftps": "fxps"}
_BARE_DOT = re.compile(r"(?<!\[)\.(?!\])")

# Safety net applied to whole reports: anything that still looks like a link.
_TEXT_SCHEME = re.compile(r"(?i)\b(?:https?|ftps?)(?=:)")
_TEXT_DOMAIN_DOT = re.compile(r"(?<=[A-Za-z0-9-])\.(?=[A-Za-z][A-Za-z0-9-])")
_TEXT_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def defang_dots(text: str) -> str:
    """Replace every bare '.' with '[.]' (idempotent)."""
    return _BARE_DOT.sub("[.]", text)


def defang_domain(domain: str) -> str:
    return defang_dots(domain)


def defang_email(address: str) -> str:
    return defang_dots(address)


def defang_url(url: str) -> str:
    """hxxp://evil[.]com/login[.]php style: no part of the result is clickable."""
    url = url.strip()
    match = _SCHEME_RE.match(url)
    if match and match.group(1).lower() not in ("hxxp", "hxxps", "fxp", "fxps"):
        scheme = match.group(1).lower()
        rest = url[match.end():]
        if scheme in _DEFANGED_SCHEMES:
            url = _DEFANGED_SCHEMES[scheme] + ":" + rest
        else:
            # mailto:, javascript:, data: ... break the scheme separator instead.
            url = scheme + "[:]" + rest
    return defang_dots(url)


def _defang_scheme_word(match: re.Match) -> str:
    word = match.group(0).lower()
    if word.startswith("f"):
        return "fxps" if word.endswith("s") else "fxp"
    return "hxxps" if word.endswith("s") else "hxxp"


def defang_text(text: str) -> str:
    """Last-line safety net over a finished report.

    Rewrites any remaining http/https/ftp scheme and any bare dot inside
    something shaped like a domain name or IPv4 address.
    """
    text = _TEXT_SCHEME.sub(_defang_scheme_word, text)
    text = _TEXT_IPV4.sub(lambda m: defang_dots(m.group(0)), text)
    return _TEXT_DOMAIN_DOT.sub("[.]", text)
