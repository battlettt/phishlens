"""Lexical URL analysis.

URLs are only ever treated as text: nothing is fetched, resolved, or opened.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import unquote

from . import domains
from .defang import defang_domain, defang_url
from .verdict import HIGH, LOW, MEDIUM, Finding, Verdict, decide

SHORTENERS = frozenset({
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
    "bl.ink", "t.ly", "s.id", "lnkd.in", "qrco.de", "v.gd", "shorte.st",
    "adf.ly", "tr.im", "x.co", "soo.gd", "clck.ru", "u.to", "trib.al", "ift.tt",
    "dlvr.it", "short.io", "surl.li", "linktr.ee", "urlz.fr", "2no.co",
})

# TLDs that are cheap or free and heavily abused in phishing campaigns.
SUSPICIOUS_TLDS = frozenset({
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click",
    "link", "country", "kim", "men", "loan", "download", "racing", "review",
    "stream", "gdn", "bid", "win", "date", "faith", "party", "science",
    "cricket", "accountant", "rest", "cam", "icu", "buzz", "cyou", "monster",
    "sbs", "quest", "cfd", "bond", "lol", "mom", "fit", "beauty", "hair",
})

# Email-marketing click trackers: link text and href legitimately differ.
TRACKING_DOMAINS = frozenset({
    "list-manage.com", "mcsv.net", "sendgrid.net", "mandrillapp.com", "rs6.net",
    "exacttarget.com", "hubspotlinks.com", "hs-sites.com", "klclick.com",
    "klclick1.com", "mailgun.org", "createsend.com", "cmail19.com", "cmail20.com",
    "mailchimp.com", "awstrack.me", "sparkpostmail.com", "safelinks.protection.outlook.com",
})

LOGIN_WORDS = ("login", "log-in", "signin", "sign-in", "logon", "verify", "account",
               "password", "passwd", "secure", "update", "banking", "wallet", "auth",
               "webscr", "confirm", "credential", "unlock", "billing", "payment")

# "invoice.pdf" in link text is a file name, not a site name.
FILE_EXTENSIONS = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt",
                             "htm", "html", "php", "asp", "aspx", "jpg", "jpeg", "png",
                             "gif", "exe", "csv", "rtf", "odt"})

TRACKING_TITLE = "The link text and the real destination differ (tracking link)"

DANGEROUS_SCHEMES = frozenset({"javascript", "data", "vbscript"})
OPAQUE_SCHEMES = frozenset({"mailto", "tel", "sms", "javascript", "data", "vbscript", "about"})
NORMAL_PORTS = {"http": 80, "https": 443, "ftp": 21}

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
_PLAIN_URL_RE = re.compile(r"(?i)\b(?:(?:https?|ftp)://|www\.)[^\s<>\"'`]+")
_HOST_IN_TEXT_RE = re.compile(
    r"(?i)(?:\b[a-z][a-z0-9+.-]*://)?((?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]*"
    r"[a-z0-9¡-￿])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]+))\b")


@dataclass(frozen=True)
class ParsedUrl:
    original: str
    scheme: str        # "" when the pasted text had no scheme
    userinfo: str      # anything before '@' in the authority
    host: str          # lowercase, as written (Unicode, punycode, or IP)
    port: str          # "" when no port was written
    rest: str          # path, query, and fragment


@dataclass(frozen=True)
class UrlReport:
    url: str
    defanged: str
    host: str
    display_text: str | None
    findings: tuple[Finding, ...]
    verdict: Verdict


def refang(text: str) -> str:
    """Undo common defanging so already-defanged URLs can be analyzed."""
    text = re.sub(r"(?i)\bhxxp", "http", text)
    text = re.sub(r"(?i)\bfxp", "ftp", text)
    return (text.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
            .replace("[://]", "://").replace("[:]", ":"))


def parse_url(raw: str) -> ParsedUrl:
    text = refang(raw.strip().strip("<>\"'"))
    scheme, rest = "", text
    match = _SCHEME_RE.match(text)
    if match:
        candidate = match.group(1).lower()
        after = text[match.end():]
        if after[:2] in ("//", "\\\\", "/\\", "\\/") or candidate in OPAQUE_SCHEMES:
            scheme, rest = candidate, after
    if scheme in OPAQUE_SCHEMES:
        host = ""
        if scheme == "mailto":
            host = rest.split("?", 1)[0].rpartition("@")[2]
        return ParsedUrl(raw, scheme, "", domains.normalize_host(host), "", rest)
    # Browsers treat backslashes like forward slashes in web addresses.
    rest = rest.lstrip("/\\")
    authority = re.match(r"[^/\\?#]*", rest).group(0)
    remainder = rest[len(authority):]
    userinfo, _, hostport = authority.rpartition("@")
    port = ""
    if hostport.startswith("["):
        host, _, tail = hostport[1:].partition("]")
        port = tail[1:] if tail.startswith(":") else ""
    elif hostport.count(":") == 1:
        host, port = hostport.split(":")
    else:
        host = hostport
    return ParsedUrl(raw, scheme, userinfo, host.lower().rstrip("."), port, remainder)


def _ip_literal(host: str) -> tuple[str | None, bool]:
    """Return (dotted IP, obfuscated?) when the host is a numeric address."""
    try:
        return str(ipaddress.ip_address(host)), False
    except ValueError:
        pass
    if re.fullmatch(r"\d{4,10}", host) and int(host) < 2 ** 32:
        return str(ipaddress.IPv4Address(int(host))), True
    if re.fullmatch(r"0x[0-9a-f]{1,8}", host):
        return str(ipaddress.IPv4Address(int(host, 16))), True
    parts = host.split(".")
    if len(parts) == 4 and all(re.fullmatch(r"0x[0-9a-f]+|\d+", p) for p in parts):
        try:
            values = [int(p, 16) if p.startswith("0x") else int(p, 8) if len(p) > 1 and p.startswith("0")
                      else int(p) for p in parts]
        except ValueError:
            return None, False
        if all(v < 256 for v in values):
            return ".".join(map(str, values)), True
    return None, False


def host_from_text(text: str) -> str | None:
    """Find the site name a piece of link text appears to promise, if any."""
    for match in _HOST_IN_TEXT_RE.finditer(refang(text)):
        host = match.group(1).lower()
        written_as_link = "://" in match.group(0) or host.startswith("www.")
        if written_as_link or host.rsplit(".", 1)[-1] not in FILE_EXTENSIONS:
            return host
    return None


def analyze_url(raw: str, display_text: str | None = None) -> UrlReport:
    parsed = parse_url(raw)
    findings: list[Finding] = []
    add = lambda sev, title, detail: findings.append(Finding(sev, title, detail))
    host = domains.normalize_host(unquote(parsed.host))
    shown_host = defang_domain(host) if host else "(none)"

    if parsed.scheme in DANGEROUS_SCHEMES:
        add(HIGH, f"The link runs code or embeds content ({parsed.scheme}:) instead of opening a website",
            f"A '{parsed.scheme}:' link does not go to a normal web page. Attackers use it to run "
            "scripts or show a fake page built into the link itself.")
        return _finish(raw, host, display_text, findings)
    if parsed.scheme == "file":
        add(MEDIUM, "The link points to a file on a computer or network share",
            "'file:' links open files directly. They can be used to leak your Windows "
            "login details or run something from a shared folder.")
    if not host and parsed.scheme not in OPAQUE_SCHEMES:
        add(MEDIUM, "The link has no site name",
            "PhishLens could not find a website name in this link, which usually means "
            "it is broken or deliberately malformed.")
        return _finish(raw, host, display_text, findings)

    if parsed.userinfo:
        fake = parsed.userinfo.split(":")[0]
        add(HIGH, "The link uses an '@' trick to hide where it really goes",
            f"Everything before the '@' ('{defang_domain(unquote(fake))}') is ignored by "
            f"browsers. The link really goes to {shown_host}.")

    if host != domains.normalize_host(parsed.host):
        add(MEDIUM, "The site name is disguised with percent-encoding",
            f"The site name is written with %-codes; it decodes to {shown_host}. Real sites "
            "do not need to hide their own name.")

    ip, obfuscated = _ip_literal(host)
    if ip:
        if obfuscated:
            add(HIGH, "The site is a disguised numeric IP address",
                f"'{shown_host}' is the IP address {defang_domain(ip)} written in an unusual "
                "number format so it does not look like an address. Real companies do not do this.")
        else:
            add(MEDIUM, "The link goes to a raw IP address instead of a website name",
                f"It points straight at {defang_domain(ip)}. Legitimate companies almost "
                "always use their own domain name; a bare number hides who runs the server.")
    elif host:
        _check_domain(host, findings)

    scheme = parsed.scheme or ""
    if parsed.port and parsed.port.isdigit() and int(parsed.port) != NORMAL_PORTS.get(scheme, -1):
        add(MEDIUM, f"The link uses an unusual port ({parsed.port})",
            f"Normal websites use the standard port. A link to port {parsed.port} often means a "
            "temporary or improvised server.")
    elif parsed.port and not parsed.port.isdigit():
        add(MEDIUM, "The site part of the link is malformed",
            "The text after ':' in the site name is not a valid port number, which is a "
            "common way to confuse link checkers.")

    lowered = unquote(parsed.rest).lower()
    if scheme == "http":
        word = next((w for w in LOGIN_WORDS if w in lowered), None)
        if word:
            add(MEDIUM, "A sign-in style page is served over plain http",
                f"The address contains '{word}' but uses http, not https, so anything typed "
                "there would travel unencrypted. Real sign-in pages always use https.")
    nested = re.search(r"(?:https?|hxxps?)(?::|%3a)(?://|%2f%2f)([^&\s/%]+)", lowered)
    if nested:
        add(LOW, "The link carries another web address inside it",
            f"It contains a second address ({defang_domain(nested.group(1))}). Sites that "
            "forward you on like this (open redirects) are used to hide the final destination.")

    if display_text:
        _check_display_text(display_text, host, findings)

    return _finish(raw, host, display_text, findings)


def _check_domain(host: str, findings: list[Finding]) -> None:
    add = lambda sev, title, detail: findings.append(Finding(sev, title, detail))
    unicode_host = domains.to_unicode(host)
    ascii_host = domains.to_ascii(host)
    reg = domains.registrable_domain(ascii_host)
    shown = defang_domain(ascii_host)

    if domains.has_non_ascii(unicode_host):
        add(MEDIUM, "The site name uses international (look-alike) characters",
            f"{shown} is punycode for '{defang_domain(unicode_host)}'. Letters from other "
            "alphabets can look identical to normal ones, so the name may not be what it seems.")

    lookalike = domains.brand_lookalike(ascii_host)
    if lookalike:
        title = {"lookalike": f"The site name imitates {lookalike.brand.name}",
                 "subdomain": f"{lookalike.brand.name}'s name is used as a decoy at the front of the address",
                 "contains": f"The site name borrows the {lookalike.brand.name} name"}[lookalike.kind]
        add(HIGH, title, lookalike.explain(defang_domain(unicode_host)))

    if reg in SHORTENERS or ascii_host in SHORTENERS:
        add(MEDIUM, "The link uses a URL shortener that hides the real destination",
            f"{defang_domain(reg)} is a link-shortening service. PhishLens does not open links, "
            "so the final site cannot be checked; phishers use shorteners for exactly that reason.")

    subs = [label for label in domains.subdomain_labels(ascii_host) if label != "www"]
    if len(subs) >= 3:
        add(MEDIUM, f"The address has an unusual number of subdomains ({len(subs)})",
            f"The part that decides where it goes is {defang_domain(reg)}; the long chain "
            "before it is usually there to bury that part out of sight.")

    if domains.tld(ascii_host) in SUSPICIOUS_TLDS:
        add(LOW, f"The site uses the .{domains.tld(ascii_host)} ending, which is often abused",
            f"Many .{domains.tld(ascii_host)} domains are cheap or free to register and show "
            "up often in phishing. This alone is not proof.")

    if domains.registrable_domain(unicode_host).split(".")[0].count("-") >= 3:
        add(LOW, "The domain name is a long string of hyphenated words",
            f"Names like {defang_domain(reg)} are typical of throwaway phishing domains.")


def _check_display_text(text: str, host: str, findings: list[Finding]) -> None:
    shown = host_from_text(text)
    if not shown:
        return
    if domains.same_organization(shown, host):
        return
    actual_reg = domains.registrable_domain(domains.to_ascii(host))
    if actual_reg in TRACKING_DOMAINS or domains.to_ascii(host).endswith(".safelinks.protection.outlook.com"):
        findings.append(Finding(MEDIUM, TRACKING_TITLE,
            f"The text shows {defang_domain(shown)} but the link goes to {defang_domain(actual_reg)}, "
            "an email click-tracking service. That is common in newsletters, but you cannot "
            "see the final site."))
        return
    findings.append(Finding(HIGH, "The link text shows one site but the link goes to another",
        f"You see '{defang_url(text.strip())}', but clicking would take you to "
        f"{defang_domain(host)}. Showing a trusted address while linking elsewhere is a "
        "classic phishing trick."))


def _finish(raw: str, host: str, display_text: str | None, findings: list[Finding]) -> UrlReport:
    return UrlReport(raw, defang_url(refang(raw.strip())), host, display_text,
                     tuple(findings), decide(findings, subject="link"))


# --- extracting links from pasted text -----------------------------------------

class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.text: list[str] = []
        self._href: str | None = None
        self._label: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._close()
            href = dict(attrs).get("href")
            if href:
                self._href, self._label = href.strip(), []

    def handle_endtag(self, tag):
        if tag == "a":
            self._close()

    def handle_data(self, data):
        # Link labels are only what a link claims to be, so they are kept apart.
        if self._href is not None:
            self._label.append(data)
        else:
            self.text.append(data)

    def _close(self):
        if self._href is not None:
            self.links.append((self._href, " ".join("".join(self._label).split())))
        self._href = None

    def close(self):
        super().close()
        self._close()


def _clean_plain(url: str) -> str:
    url = url.rstrip(".,;:!?")
    while url.endswith(")") and url.count("(") < url.count(")"):
        url = url[:-1]
    while url.endswith("]") and url.count("[") < url.count("]"):
        url = url[:-1]
    return url


def extract_links(text: str, limit: int = 50) -> list[tuple[str, str | None]]:
    """Pull URLs out of pasted text or HTML as (url, link text or None) pairs."""
    found: dict[str, str | None] = {}
    plain_source = text
    if re.search(r"(?i)<a\s", text) or re.search(r"(?i)<(html|body|div|p|table)\b", text):
        parser = _LinkParser()
        parser.feed(text)
        parser.close()
        for href, label in parser.links:
            scheme = (_SCHEME_RE.match(href).group(1).lower() if _SCHEME_RE.match(href) else "")
            if scheme in ("http", "https", "ftp", "file") or scheme in DANGEROUS_SCHEMES \
                    or href.lower().startswith("www."):
                found.setdefault(href, label or None)
        plain_source = " ".join(parser.text)
    for match in _PLAIN_URL_RE.finditer(plain_source):
        found.setdefault(_clean_plain(match.group(0)), None)
    return list(found.items())[:limit]


def analyze_text(text: str) -> list[UrlReport]:
    """Analyze one pasted URL, or every link inside pasted HTML or text."""
    stripped = text.strip()
    if not stripped:
        return []
    if "<" in stripped and re.search(r"(?i)<a\s", stripped):
        return [analyze_url(url, label) for url, label in extract_links(stripped)]
    return [analyze_url(stripped)]

