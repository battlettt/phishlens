"""Turn individual findings into a plain-English verdict with advice."""

from __future__ import annotations

from dataclasses import dataclass

INFO, LOW, MEDIUM, HIGH = "info", "low", "medium", "high"
POINTS = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 4}
RANK = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3}

LOOKS_SAFE = "LOOKS SAFE"
SUSPICIOUS = "SUSPICIOUS"
LIKELY_PHISHING = "LIKELY PHISHING"

# Any single HIGH finding, or this many points, means LIKELY PHISHING.
PHISHING_POINTS = 6
SUSPICIOUS_POINTS = 2


@dataclass(frozen=True)
class Finding:
    severity: str  # INFO, LOW, MEDIUM, or HIGH
    title: str     # one short sentence
    detail: str    # plain-English explanation of why it matters


@dataclass(frozen=True)
class Verdict:
    level: str
    summary: str
    reasons: tuple[Finding, ...]  # warning signs, most serious first
    notes: tuple[Finding, ...]    # context that did not count against it
    advice: tuple[str, ...]
    points: int


_SUMMARIES = {
    ("email", LIKELY_PHISHING): (
        "This email shows strong signs of phishing. It is very likely not from who it "
        "claims to be, or it tries to send you somewhere dangerous."),
    ("email", SUSPICIOUS): (
        "This email has warning signs. It may turn out to be harmless, but treat it with "
        "caution until you have checked it another way."),
    ("email", LOOKS_SAFE): (
        "No warning signs were found in the pasted headers and links. The sender checks "
        "that could be verified are consistent with who the email says it is from."),
    ("link", LIKELY_PHISHING): (
        "This link shows strong signs of phishing. It is built to look like somewhere "
        "you trust while really going somewhere else, or it hides where it goes."),
    ("link", SUSPICIOUS): (
        "This link has warning signs. It may be harmless, but do not open it until you "
        "have confirmed where it really goes."),
    ("link", LOOKS_SAFE): (
        "No warning signs were found in how this link is written."),
}

_ADVICE = {
    ("email", LIKELY_PHISHING): (
        "Do not click any links, open any attachments, or reply.",
        "Do not enter passwords, codes, or payment details anywhere this email points you.",
        "Report it: use your email app's 'Report phishing' button or forward it to your "
        "IT or security team, then delete it.",
        "If you already clicked or typed a password, change that password on the real "
        "website (type the address yourself) and tell your IT team or bank.",
    ),
    ("email", SUSPICIOUS): (
        "Do not click links or open attachments yet.",
        "Check it another way: type the company's web address yourself, or contact the "
        "sender using a phone number or address you already trust.",
        "If you cannot confirm it is genuine, report it as phishing.",
    ),
    ("email", LOOKS_SAFE): (
        "Nothing here looks wrong, but PhishLens can only judge the text you pasted.",
        "Stay careful with unexpected requests for passwords, payments, or gift cards, "
        "even from senders that pass these checks.",
    ),
    ("link", LIKELY_PHISHING): (
        "Do not open this link.",
        "Do not enter passwords, codes, or payment details on the page it leads to.",
        "If it came in an email or message, report it as phishing and delete it.",
        "If you need the real site, type its address yourself or use a bookmark.",
    ),
    ("link", SUSPICIOUS): (
        "Do not open this link until you know where it really goes.",
        "Go to the site by typing its address yourself instead of using this link.",
        "If someone sent it to you unexpectedly, ask them through another channel.",
    ),
    ("link", LOOKS_SAFE): (
        "The link looks normal, but PhishLens only checks how it is written, not the "
        "page behind it.",
        "Still make sure the site name is one you expect before signing in.",
    ),
}


def decide(findings: list[Finding] | tuple[Finding, ...], subject: str = "email") -> Verdict:
    """Combine findings into LOOKS SAFE, SUSPICIOUS, or LIKELY PHISHING."""
    warnings = [f for f in findings if f.severity != INFO]
    warnings.sort(key=lambda f: -RANK[f.severity])
    notes = tuple(f for f in findings if f.severity == INFO)
    points = sum(POINTS[f.severity] for f in warnings)
    if any(f.severity == HIGH for f in warnings) or points >= PHISHING_POINTS:
        level = LIKELY_PHISHING
    elif points >= SUSPICIOUS_POINTS:
        level = SUSPICIOUS
    else:
        level = LOOKS_SAFE
    return Verdict(level, _SUMMARIES[(subject, level)], tuple(warnings), notes,
                   _ADVICE[(subject, level)], points)


def worst(findings: list[Finding] | tuple[Finding, ...]) -> str:
    return max((f.severity for f in findings), key=RANK.__getitem__, default=INFO)
