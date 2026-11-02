"""Email header analysis from pasted text.

Only the pasted text is read. No mailbox is opened, no mail server is
contacted, and no DNS lookups are made: SPF, DKIM, and DMARC are judged from
the Authentication-Results the receiving server already wrote into the headers.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email import policy
from email.header import decode_header, make_header
from email.parser import Parser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

from . import domains
from .defang import defang_domain, defang_email
from .urls import TRACKING_TITLE, UrlReport, analyze_url, extract_links
from .verdict import HIGH, INFO, LOW, MEDIUM, Finding, Verdict, decide, worst

PASS = "pass"
FAILS = {"fail", "softfail", "permerror"}
KNOWN_HEADERS = ("from", "received", "authentication-results", "return-path", "message-id",
                 "reply-to", "to", "subject", "date", "dkim-signature", "received-spf")

ROLE_WORDS = ("support", "security", "admin", "administrator", "helpdesk", "help desk",
              "service desk", "it department", "it support", "it team", "billing",
              "accounts", "payroll", "human resources", "postmaster", "webmaster",
              "mail delivery", "account team", "verification", "customer service")

_DOMAINISH = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b")


@dataclass(frozen=True)
class Address:
    display: str
    address: str

    @property
    def domain(self) -> str:
        return domains.normalize_host(self.address.rpartition("@")[2]) if "@" in self.address else ""


@dataclass(frozen=True)
class AuthResult:
    method: str
    result: str
    props: dict
    authserv: str


@dataclass(frozen=True)
class AuthCheck:
    name: str         # SPF, DKIM, DMARC
    status: str       # short label, e.g. "PASS (aligned)"
    explanation: str  # plain English


@dataclass(frozen=True)
class Hop:
    helo: str
    rdns: str
    ip: str
    by: str
    date: datetime | None


@dataclass
class HeaderReport:
    from_addr: Address | None = None
    reply_to: list[Address] = field(default_factory=list)
    return_path: str = ""
    subject: str = ""
    message_id: str = ""
    list_unsubscribe: list[str] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)  # as pasted: newest first
    auth: dict[str, AuthCheck] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    links: list[UrlReport] = field(default_factory=list)
    verdict: Verdict | None = None

    @property
    def first_hop(self) -> Hop | None:
        return _origin_hop(self.hops)


class NotHeadersError(ValueError):
    """The pasted text does not contain recognizable email headers."""


# --- parsing helpers -------------------------------------------------------------

def _unfold(value: str) -> str:
    return re.sub(r"\s*\r?\n\s+", " ", str(value)).strip()


def _decode(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except Exception:  # malformed encoded-words: show the raw text instead
        return value


def _strip_comments(value: str) -> str:
    out, depth, quoted = [], 0, False
    for ch in value:
        if ch == '"' and depth == 0:
            quoted = not quoted
        if not quoted:
            if ch == "(":
                depth += 1
                continue
            if ch == ")" and depth:
                depth -= 1
                continue
        if depth == 0:
            out.append(ch)
    return "".join(out)


def _domain_of(value: str) -> str:
    value = value.strip().strip("<>\"'")
    return domains.normalize_host(value.rpartition("@")[2]) if value else ""


def parse_authentication_results(value: str) -> list[AuthResult]:
    """Split one Authentication-Results header into method results."""
    raw = _unfold(value)
    policy_match = re.search(r"\bp=(\w+)", raw, re.I)
    parts = [p.strip() for p in _strip_comments(raw).split(";")]
    authserv = ""
    if parts and "=" not in parts[0].split(" ")[0]:
        authserv = parts.pop(0).split(" ")[0] if parts[0] else ""
    results = []
    for part in parts:
        tokens = part.split()
        if not tokens or "=" not in tokens[0]:
            continue
        method, _, result = tokens[0].partition("=")
        props = {}
        for token in tokens[1:]:
            key, sep, val = token.partition("=")
            if sep:
                props[key.lower()] = val.strip("\"'").lower()
        if method.lower() == "dmarc" and policy_match:
            props.setdefault("policy", policy_match.group(1).lower())
        results.append(AuthResult(method.lower(), result.lower(), props, authserv.lower()))
    return results


def parse_received(value: str) -> Hop:
    text = _unfold(value)
    helo = rdns = ip = by = ""
    date = None
    m = re.match(r"(?i)\s*from\s+(\S+)(?:\s+\(([^)]*)\))?", text)
    if m:
        helo = m.group(1).strip("[]").rstrip(".").lower()
        info = m.group(2) or ""
        exim_helo = re.search(r"(?i)helo=([^\s)\]]+)", info)
        if exim_helo:
            helo = exim_helo.group(1).strip("[]").rstrip(".").lower()
        first = info.split()[0].rstrip(".").lower() if info.split() else ""
        if first and "=" not in first and not first.startswith("["):
            rdns = first
        ip_match = re.search(r"\[(?:ipv6:)?([0-9a-fA-F:.]+)\]", info) or \
            re.search(r"\[(?:ipv6:)?([0-9a-fA-F:.]+)\]", m.group(1))
        if ip_match:
            ip = ip_match.group(1)
        elif domains.is_ip(helo):
            ip = helo
    b = re.search(r"(?i)\bby\s+([^\s;()]+)", text)
    if b:
        by = b.group(1).rstrip(".").lower()
    if ";" in text:
        try:
            date = parsedate_to_datetime(text.rsplit(";", 1)[1].strip())
        except (TypeError, ValueError, IndexError):
            date = None
    return Hop(helo, rdns, ip, by, date)


def _is_hostname(name: str) -> bool:
    return bool(name) and "." in name and not domains.is_ip(name) and name != "unknown"


# Internal networks only: a hop from here is the sender's own machine or LAN.
_INTERNAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10"))


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == net.version and addr in net for net in _INTERNAL_NETWORKS)


def _origin_hop(hops: list[Hop]) -> Hop | None:
    """The oldest hop that came from a real, public server."""
    candidates = [h for h in reversed(hops) if h.helo or h.rdns or h.ip]
    for hop in candidates:
        if hop.ip and _is_private(hop.ip):
            continue
        if not (_is_hostname(hop.rdns) or _is_hostname(hop.helo) or hop.ip):
            continue
        if hop.helo in ("localhost", "127.0.0.1") and not hop.ip:
            continue
        return hop
    return candidates[0] if candidates else None


def _normalize(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n").lstrip("\n")
    if text.startswith("From ") and not re.match(r"From:\s", text):
        text = text.split("\n", 1)[1] if "\n" in text else ""  # mbox separator line
    return text


def _body_text(msg) -> str:
    chunks = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_content_maintype() not in ("text", ""):
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            payload = str(part.get_payload() or "").encode("utf-8", "replace")
        charset = part.get_content_charset() or "utf-8"
        try:
            chunks.append(payload.decode(charset, "replace"))
        except LookupError:
            chunks.append(payload.decode("utf-8", "replace"))
    return "\n".join(chunks)


# --- analysis ----------------------------------------------------------------------

def analyze_headers(text: str) -> HeaderReport:
    """Analyze pasted headers (and any pasted body) entirely in memory."""
    msg = Parser(policy=policy.compat32).parsestr(_normalize(text))
    present = {k.lower() for k in msg.keys()}
    if not present.intersection(KNOWN_HEADERS):
        raise NotHeadersError(
            "No email headers were found. Paste the full header block, which contains "
            "lines such as 'From:', 'Received:' and 'Authentication-Results:'.")

    report = HeaderReport()
    findings = report.findings
    add = lambda sev, title, detail: findings.append(Finding(sev, title, detail))

    if msg.get("From"):
        display, address = parseaddr(_unfold(msg.get("From")))
        report.from_addr = Address(_decode(display).strip(), address.strip().lower())
    report.reply_to = [Address(_decode(d).strip(), a.strip().lower())
                       for d, a in getaddresses([_unfold(v) for v in msg.get_all("Reply-To") or []]) if a]
    if msg.get("Return-Path"):
        report.return_path = parseaddr(_unfold(msg.get("Return-Path")))[1].lower()
    report.subject = _decode(_unfold(msg.get("Subject", "")))
    report.message_id = _unfold(msg.get("Message-ID", ""))
    if msg.get("List-Unsubscribe"):
        report.list_unsubscribe = re.findall(r"<([^>]+)>", _unfold(msg.get("List-Unsubscribe")))
    report.hops = [parse_received(v) for v in msg.get_all("Received") or []]

    from_domain = report.from_addr.domain if report.from_addr else ""
    rp_domain = _domain_of(report.return_path)

    auth = _authentication(msg, report, from_domain, rp_domain)
    _check_sender(report, from_domain, rp_domain, auth["dmarc_ok"])
    _check_received(report, from_domain, rp_domain, auth)
    _check_message_id(report, from_domain, rp_domain, auth)
    _check_unsubscribe(report)

    body = _body_text(msg) if msg.get_payload() else ""
    for url, label in extract_links(body):
        link = analyze_url(url, label)
        report.links.append(link)
        reasons = link.verdict.reasons
        if auth["dmarc_ok"]:
            # Click tracking is normal in authenticated newsletters.
            reasons = tuple(f for f in reasons if f.title != TRACKING_TITLE)
            if len(reasons) < len(link.verdict.reasons):
                add(INFO, f"A link in the message goes through a click-tracking service: {link.defanged}",
                    "That is normal for newsletters, and the sender passed authentication.")
        level = worst(reasons)
        if level in (MEDIUM, HIGH):
            word = "dangerous" if level == HIGH else "suspicious"
            add(level, f"A link in the message is {word}: {link.defanged}",
                f"{reasons[0].title}. {reasons[0].detail}")
        elif level == LOW:
            add(INFO, f"A link in the message has a minor warning sign: {link.defanged}",
                reasons[0].title + ".")

    report.verdict = decide(findings, subject="email")
    return report


def _authentication(msg, report: HeaderReport, from_domain: str, rp_domain: str) -> dict:
    """Report SPF, DKIM, and DMARC separately, from the pasted results only."""
    add = lambda sev, title, detail: report.findings.append(Finding(sev, title, detail))
    headers = [parse_authentication_results(v) for v in msg.get_all("Authentication-Results") or []]
    headers = [h for h in headers if h]
    dkim_sig_domains = [d.lower() for v in msg.get_all("DKIM-Signature") or []
                        for d in re.findall(r"(?:^|;)\s*d=([^;\s]+)", _unfold(v))]
    received_spf = [_unfold(v).split()[0].lower() for v in msg.get_all("Received-SPF") or [] if _unfold(v)]

    def first(method):
        for h in headers:
            found = [r for r in h if r.method == method]
            if found:
                return found
        return []

    spf_results, dkim_results, dmarc_results = first("spf"), first("dkim"), first("dmarc")
    shown_from = defang_domain(from_domain) if from_domain else "the From address"

    # SPF ----------------------------------------------------------------------
    spf = spf_results[0] if spf_results else None
    spf_result = spf.result if spf else (received_spf[0] if received_spf else "")
    spf_domain = ""
    if spf:
        spf_domain = _domain_of(spf.props.get("smtp.mailfrom", "")) or _domain_of(spf.props.get("smtp.helo", ""))
    spf_domain = spf_domain or rp_domain
    spf_aligned = bool(spf_domain) and domains.same_organization(spf_domain, from_domain)
    spf_ok = spf_result == PASS and spf_aligned

    # DKIM ---------------------------------------------------------------------
    dkim_info = []
    for r in dkim_results:
        d = r.props.get("header.d") or _domain_of(r.props.get("header.i", ""))
        if not d and len(dkim_sig_domains) == 1:
            d = dkim_sig_domains[0]
        dkim_info.append((r.result, d, domains.same_organization(d, from_domain)))
    dkim_ok = any(res == PASS and aligned for res, _, aligned in dkim_info)

    dmarc = dmarc_results[0] if dmarc_results else None
    dmarc_ok = (dmarc.result == PASS) if dmarc else (spf_ok or dkim_ok)

    if not headers and not received_spf:
        add(MEDIUM, "No authentication results in the pasted headers",
            "There is no Authentication-Results header, so nothing confirms who really sent "
            "this. If you copied only part of the headers, paste the complete header block.")

    report.auth["SPF"] = _spf_check(spf_result, spf_domain, spf_aligned, shown_from, bool(headers or received_spf))
    if spf_result in ("fail", "permerror"):
        add(LOW if dmarc_ok else MEDIUM, "SPF failed",
            f"The server that delivered this was not authorized to send mail for "
            f"{defang_domain(spf_domain or 'the sender domain')}."
            + (" DKIM still vouches for the sender, which happens with forwarded mail." if dmarc_ok else
               " That is a common sign of a forged sender."))
    elif spf_result == "softfail":
        add(LOW, "SPF soft-failed",
            f"The owner of {defang_domain(spf_domain or 'the sender domain')} says this server "
            "probably should not be sending its mail.")
    elif spf_result == PASS and not spf_aligned and spf_domain and from_domain and not dmarc_ok:
        add(LOW, "SPF passed, but for a different domain than the From address",
            f"SPF only vouches for {defang_domain(spf_domain)}, not for {shown_from}.")

    report.auth["DKIM"] = _dkim_check(dkim_info, shown_from, bool(headers))
    if any(res in FAILS for res, _, _ in dkim_info) and not dkim_ok:
        add(LOW if dmarc_ok else MEDIUM, "DKIM signature failed",
            "The message's digital signature did not check out, so it may have been "
            "altered or the signature was forged.")
    elif headers and not dkim_info and not dmarc_ok:
        add(LOW, "The message is not digitally signed (no DKIM)",
            "Most legitimate companies sign their mail with DKIM; this message has no signature result.")

    report.auth["DMARC"] = _dmarc_check(dmarc, spf_ok, dkim_ok, shown_from, bool(headers))
    if dmarc and dmarc.result in FAILS:
        pol = dmarc.props.get("policy", "")
        add(HIGH, "DMARC failed: the From address is not authenticated",
            f"Neither SPF nor DKIM proved that this really came from {shown_from}."
            + (f" The domain owner's policy (p={pol}) says such mail should be "
               f"{'rejected' if pol == 'reject' else 'treated as suspicious' if pol == 'quarantine' else 'monitored'}."
               if pol else ""))
    elif headers and not dmarc_ok and from_domain:
        add(MEDIUM, f"Nothing proves this email really came from {shown_from}",
            "No DMARC pass was recorded and neither SPF nor DKIM passed for a domain "
            "matching the From address.")

    _check_contradictions(report, headers, received_spf, spf_result, spf_domain, rp_domain,
                          from_domain, dmarc, spf_ok, dkim_ok)
    return {"dmarc_ok": dmarc_ok, "spf_domain": spf_domain,
            "dkim_domains": [d for _, d, _ in dkim_info if d] + dkim_sig_domains}


def _spf_check(result, domain, aligned, shown_from, any_auth) -> AuthCheck:
    shown = defang_domain(domain) if domain else "the envelope sender"
    if not result:
        text = ("No SPF result was found in the pasted headers." if any_auth else
                "No SPF result was found (no Authentication-Results header was pasted).")
        return AuthCheck("SPF", "NOT REPORTED", text)
    if result == PASS:
        if aligned:
            return AuthCheck("SPF", "PASS (aligned)",
                             f"The sending server was authorized to send mail for {shown}, which "
                             f"matches the From domain ({shown_from}).")
        return AuthCheck("SPF", "PASS (not aligned)",
                         f"The sending server was authorized to send mail for {shown}, but that "
                         f"is not the From domain ({shown_from}). On its own this does not prove "
                         "who wrote the email; it is normal when a mailing service sends for a company.")
    if result == "fail":
        return AuthCheck("SPF", "FAIL", f"The sending server is NOT on the list of servers allowed "
                         f"to send mail for {shown}.")
    if result == "softfail":
        return AuthCheck("SPF", "SOFTFAIL", f"The owner of {shown} says this server probably "
                         "should not be sending its mail.")
    if result in ("neutral", "none"):
        return AuthCheck("SPF", result.upper(), f"{shown} does not publish a clear SPF rule, so "
                         "SPF gives no assurance either way.")
    return AuthCheck("SPF", result.upper(), f"SPF for {shown} could not be checked ({result}), so it "
                     "gives no assurance.")


def _dkim_check(info, shown_from, any_auth) -> AuthCheck:
    if not info:
        return AuthCheck("DKIM", "NOT REPORTED", "No DKIM result was found in the pasted headers; "
                         "the message does not appear to be digitally signed." if any_auth else
                         "No DKIM result was found (no Authentication-Results header was pasted).")
    passing = [(d, aligned) for res, d, aligned in info if res == PASS]
    if any(aligned for _, aligned in passing):
        d = next(d for d, aligned in passing if aligned)
        return AuthCheck("DKIM", "PASS (aligned)",
                         f"The message carries a valid digital signature from {defang_domain(d)}, "
                         f"which matches the From domain ({shown_from}), and it was not altered in transit.")
    if passing:
        d = passing[0][0] or "an unnamed domain"
        return AuthCheck("DKIM", "PASS (not aligned)",
                         f"There is a valid signature, but it is from {defang_domain(d)}, not from the "
                         f"From domain ({shown_from}). It proves who relayed it, not who it claims to be from.")
    res, d, _ = info[0]
    signer = f" from {defang_domain(d)}" if d else ""
    if res in FAILS:
        return AuthCheck("DKIM", res.upper(), f"The digital signature{signer} did not verify. The message "
                         "may have been altered, or the signature was forged.")
    if res == "none":
        return AuthCheck("DKIM", "NONE", "The message is not digitally signed.")
    return AuthCheck("DKIM", res.upper(), f"The signature{signer} could not be checked ({res}).")


def _dmarc_check(dmarc, spf_ok, dkim_ok, shown_from, any_auth) -> AuthCheck:
    computed = ("SPF passed for a matching domain" if spf_ok else
                "DKIM passed for a matching domain" if dkim_ok else "")
    if dmarc is None:
        if not any_auth:
            return AuthCheck("DMARC", "NOT REPORTED",
                             "No DMARC result was found (no Authentication-Results header was pasted).")
        if computed:
            return AuthCheck("DMARC", "NOT REPORTED (alignment OK)",
                             f"No DMARC result was recorded, but {computed}, so the From address "
                             f"({shown_from}) is backed by at least one check.")
        return AuthCheck("DMARC", "NOT REPORTED (no alignment)",
                         f"No DMARC result was recorded, and neither SPF nor DKIM passed for the "
                         f"From domain ({shown_from}). Nothing ties the From address to the real sender.")
    pol = dmarc.props.get("policy", "")
    pol_text = f" The domain's policy is p={pol}." if pol else ""
    if dmarc.result == PASS:
        return AuthCheck("DMARC", "PASS",
                         f"The From domain ({shown_from}) is authenticated: SPF or DKIM passed for a "
                         f"matching domain.{pol_text}")
    if dmarc.result in FAILS:
        return AuthCheck("DMARC", "FAIL",
                         f"The From address ({shown_from}) could not be authenticated: neither SPF nor "
                         f"DKIM passed for a matching domain.{pol_text}")
    if dmarc.result == "none":
        return AuthCheck("DMARC", "NONE", f"{shown_from} publishes no DMARC policy, so the From address "
                         "is not protected against spoofing." + (f" However, {computed}." if computed else ""))
    return AuthCheck("DMARC", dmarc.result.upper(), f"DMARC could not be evaluated ({dmarc.result}).")


def _check_contradictions(report, headers, received_spf, spf_result, spf_domain, rp_domain,
                          from_domain, dmarc, spf_ok, dkim_ok) -> None:
    add = lambda sev, title, detail: report.findings.append(Finding(sev, title, detail))
    # A lower (earlier, easier to fake) header claiming pass when the top one says otherwise.
    top = {r.method: r.result for r in headers[0]} if headers else {}
    fake_pass = next((r for lower in headers[1:] for r in lower
                      if r.method in ("spf", "dkim", "dmarc") and r.result == PASS
                      and top.get(r.method, PASS) != PASS), None)
    if fake_pass:
        add(MEDIUM, "Authentication results contradict each other",
            f"A lower Authentication-Results header (from "
            f"'{defang_domain(fake_pass.authserv or 'unnamed')}') claims {fake_pass.method.upper()} "
            f"passed, but the receiving server's own check says {top[fake_pass.method]}. Fake "
            "'pass' headers added by the sender are a known trick; trust the top one.")
    if dmarc and dmarc.result == PASS:
        hfrom = dmarc.props.get("header.from", "")
        if hfrom and from_domain and not domains.same_organization(hfrom, from_domain):
            add(HIGH, "The DMARC pass is for a different domain than the From address",
                f"DMARC passed for {defang_domain(hfrom)}, but the email shows "
                f"{defang_domain(from_domain)} as the sender. The pass says nothing about the "
                "address you see.")
        elif not spf_ok and not dkim_ok and (headers[0] if headers else []) and \
                any(r.method in ("spf", "dkim") for r in headers[0]):
            add(MEDIUM, "DMARC says pass, but SPF and DKIM do not back it up",
                "DMARC can only pass when SPF or DKIM passes for a domain matching the From "
                "address. Neither did here, so the DMARC pass does not add up.")
    if spf_result == PASS and spf_domain and rp_domain and not domains.same_organization(spf_domain, rp_domain):
        add(MEDIUM, "SPF was checked for a different domain than the Return-Path",
            f"SPF passed for {defang_domain(spf_domain)}, but the Return-Path says "
            f"{defang_domain(rp_domain)}. These should normally match.")
    ar_spf = next((r.result for h in headers[:1] for r in h if r.method == "spf"), "")
    if received_spf and ar_spf and received_spf[0] != ar_spf and PASS in (received_spf[0], ar_spf):
        add(MEDIUM, "The SPF results in different headers disagree",
            f"Received-SPF says '{received_spf[0]}' but Authentication-Results says '{ar_spf}'.")


def _check_sender(report: HeaderReport, from_domain: str, rp_domain: str, dmarc_ok: bool) -> None:
    add = lambda sev, title, detail: report.findings.append(Finding(sev, title, detail))
    sender = report.from_addr
    if not sender or not sender.address:
        add(MEDIUM, "There is no usable From address",
            "Every genuine email names its sender. A missing or broken From line is a red flag.")
        return
    shown_addr = defang_email(sender.address)

    # Display-name spoofing.
    display = sender.display
    named = _DOMAINISH.search(display) if display else None
    brand = domains.brand_in_text(display) if display else None
    if named and not domains.same_organization(named.group(0).split("@")[-1], from_domain):
        add(HIGH, "The sender's name shows a different email address or domain",
            f"The name reads '{defang_email(display)}', but the mail actually comes from "
            f"{shown_addr}. Putting a trusted address in the name is a common disguise.")
    elif brand and (domains.brand_owning(from_domain) is not brand or domains.is_free_mail(from_domain)):
        add(HIGH, f"The sender's name claims to be {brand.name}, but the address is not {brand.name}'s",
            f"The name says '{display}' but the address is {shown_addr}. {brand.name} sends from "
            f"its own domain (such as {defang_domain(sorted(brand.domains)[0])}), not this one.")
    elif display and domains.is_free_mail(from_domain) and \
            any(re.search(rf"\b{re.escape(w)}\b", display.lower()) for w in ROLE_WORDS):
        add(MEDIUM, "An official-sounding name is sending from a free email account",
            f"'{display}' sounds like a company department, but it comes from {shown_addr}, a "
            "free personal mailbox anyone can create.")

    checked = set()
    for label, candidates in (("From", [from_domain]), ("Reply-To", [a.domain for a in report.reply_to]),
                              ("Return-Path", [rp_domain])):
        for domain in candidates:
            if domain and domain not in checked:
                checked.add(domain)
                _check_sender_domain(report, label, domain)

    for reply in report.reply_to:
        if reply.domain and not domains.same_organization(reply.domain, from_domain):
            free = " (a free personal mailbox)" if domains.is_free_mail(reply.domain) else ""
            add(MEDIUM, "Replies would go to a different address than the sender",
                f"The email is from {shown_addr}, but pressing Reply sends your answer to "
                f"{defang_email(reply.address)}{free}. Scammers do this to receive replies "
                "while hiding behind a believable From address.")
            break

    if rp_domain and from_domain and not domains.same_organization(rp_domain, from_domain):
        if dmarc_ok:
            add(INFO, "The Return-Path domain differs from the From domain",
                f"Bounces go to {defang_domain(rp_domain)}. That is normal for mail sent through "
                "an email service, and authentication still ties the message to the sender.")
        else:
            add(MEDIUM, "The From and Return-Path domains do not match",
                f"The email claims to be from {defang_domain(from_domain)}, but the hidden "
                f"envelope sender (Return-Path) is {defang_domain(rp_domain)}, and authentication "
                "does not connect the two.")
    elif not report.return_path:
        add(INFO, "No Return-Path header was pasted",
            "The receiving server normally adds it. It may simply not have been copied.")


def _check_sender_domain(report: HeaderReport, label: str, domain: str) -> None:
    add = lambda sev, title, detail: report.findings.append(Finding(sev, title, detail))
    uni = domains.to_unicode(domain)
    if domains.has_non_ascii(uni):
        add(MEDIUM, f"The {label} domain uses international (look-alike) characters",
            f"{defang_domain(domains.to_ascii(domain))} displays as '{defang_domain(uni)}'. "
            "Letters from other alphabets can be made to look like a familiar name.")
    lookalike = domains.brand_lookalike(domain)
    if lookalike:
        add(HIGH, f"The {label} domain imitates {lookalike.brand.name}",
            lookalike.explain(defang_domain(uni)))


def _check_received(report: HeaderReport, from_domain: str, rp_domain: str, auth: dict) -> None:
    add = lambda sev, title, detail: report.findings.append(Finding(sev, title, detail))
    if not report.hops:
        add(LOW, "There are no Received lines",
            "Every delivered email records the servers it passed through. None were pasted; "
            "if you copied only some headers, paste the full block.")
        return
    origin = report.first_hop
    if origin is None or not from_domain:
        return
    claimed = {domains.registrable_domain(d) for d in
               [from_domain, rp_domain, auth["spf_domain"], *auth["dkim_domains"]] if d}
    claimed |= domains.PROVIDER_INFRASTRUCTURE.get(domains.registrable_domain(from_domain), set())
    names = [n for n in (origin.rdns, origin.helo) if _is_hostname(n)]
    orgs = {domains.registrable_domain(n) for n in names}
    where = defang_domain(origin.helo or origin.ip or "an unnamed server")
    if origin.ip and origin.ip != origin.helo:
        where += f" (IP {defang_domain(origin.ip)})"
    unconfirmed = ""
    if _is_hostname(origin.helo) and origin.rdns == "unknown":
        unconfirmed = (" The receiving server could not confirm that name: the server's real "
                       "network name is unknown, so the name it gave may be made up.")

    helo_claims = _is_hostname(origin.helo) and domains.registrable_domain(origin.helo) in claimed
    rdns_known = _is_hostname(origin.rdns)
    if helo_claims and origin.rdns and (not rdns_known or domains.registrable_domain(origin.rdns) not in claimed):
        add(MEDIUM, "The first server introduced itself with the sender's name, but its real name differs",
            f"It called itself {defang_domain(origin.helo)}, but its network name is "
            f"{defang_domain(origin.rdns)}. Anyone can claim a name when connecting; this "
            "server's real identity does not match the sender.")
    elif not orgs:
        add(LOW if not auth["dmarc_ok"] else INFO, "The first server in the delivery chain has no name",
            f"The message entered the mail system from {where}, which has no hostname to tie "
            "it to the sender.")
    elif not orgs & claimed:
        add(INFO if auth["dmarc_ok"] else LOW,
            "The first server in the delivery chain does not belong to the sender's domain",
            f"The email claims to be from {defang_domain(from_domain)} but first entered the mail "
            f"system at {where}.{unconfirmed}"
            + (" Authentication still passed, so this is likely an email service sending on "
               "the sender's behalf." if auth["dmarc_ok"] else ""))

    dated = [h.date for h in reversed(report.hops) if h.date]
    for older, newer in zip(dated, dated[1:]):
        try:
            backwards = newer < older - timedelta(minutes=10)
        except TypeError:  # mixing dates with and without time zones
            continue
        if backwards:
            add(LOW, "The delivery timestamps are out of order",
                "One server says it handled the message before the previous server sent it. "
                "Clock errors happen, but faked Received lines also look like this.")
            break


def _check_message_id(report: HeaderReport, from_domain: str, rp_domain: str, auth: dict) -> None:
    add = lambda sev, title, detail: report.findings.append(Finding(sev, title, detail))
    if not report.message_id:
        add(LOW, "There is no Message-ID",
            "Real mail servers almost always stamp a Message-ID. A missing one suggests the "
            "message was made by a crude bulk-sending tool (or it was not pasted).")
        return
    m = re.search(r"<?[^<>@\s]+@([^<>\s]+)>?", report.message_id)
    if not m:
        add(LOW, "The Message-ID is malformed",
            "It does not look like the usual <unique-id@domain> format that mail software produces.")
        return
    mid_domain = domains.normalize_host(m.group(1))
    related = {domains.registrable_domain(d) for d in
               [from_domain, rp_domain, auth["spf_domain"], *auth["dkim_domains"]] if d}
    related |= domains.PROVIDER_INFRASTRUCTURE.get(domains.registrable_domain(from_domain), set())
    if from_domain and domains.registrable_domain(mid_domain) not in related:
        add(INFO, "The Message-ID was created by a different domain",
            f"The Message-ID comes from {defang_domain(mid_domain)}. Mail services often do "
            "this, so it only matters alongside other warning signs.")


def _check_unsubscribe(report: HeaderReport) -> None:
    for target in report.list_unsubscribe:
        if target.lower().startswith(("http://", "https://")):
            link = analyze_url(target)
            for f in link.verdict.reasons:
                if f.severity in (MEDIUM, HIGH):
                    report.findings.append(Finding(f.severity, f"The unsubscribe link is suspicious: {f.title}",
                                                   f.detail))
                    return
    if report.list_unsubscribe:
        report.findings.append(Finding(INFO, "The email has a List-Unsubscribe header",
            "That is typical of newsletters and other bulk mail from established senders."))
