"""Domain helpers: registrable domains, IDN decoding, and brand look-alikes.

Everything here is lexical. No DNS lookups, no network access.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass

# Public suffixes with two labels, so "shop.example.co.uk" -> "example.co.uk".
# A small built-in list rather than the full Public Suffix List (no downloads).
MULTI_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "net.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "co.in", "net.in", "org.in", "gov.in",
    "co.za", "org.za", "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "com.hk", "com.tw", "com.sg",
    "com.mx", "com.ar", "com.tr", "com.ua", "com.pl", "com.ru", "com.my",
    "com.ph", "com.vn", "com.pk", "com.ng", "com.eg", "com.sa", "co.il",
    "co.id", "or.id", "co.th", "in.th",
})

FREE_MAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "rocketmail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com", "aol.com",
    "icloud.com", "me.com", "mac.com", "mail.com", "gmx.com", "gmx.de", "gmx.net",
    "proton.me", "protonmail.com", "yandex.ru", "yandex.com", "zoho.com",
    "mail.ru", "qq.com", "163.com", "126.com", "web.de", "tutanota.com",
})

# Mailbox providers whose mail is relayed by servers under a different name.
PROVIDER_INFRASTRUCTURE = {
    "gmail.com": {"google.com"},
    "googlemail.com": {"google.com"},
    "outlook.com": {"outlook.com", "hotmail.com", "live.com", "office365.com"},
    "hotmail.com": {"outlook.com", "hotmail.com", "live.com"},
    "live.com": {"outlook.com", "hotmail.com", "live.com"},
    "msn.com": {"outlook.com", "hotmail.com"},
    "yahoo.com": {"yahoo.com", "yahoodns.net", "yahoo.net"},
    "ymail.com": {"yahoo.com", "yahoodns.net"},
    "aol.com": {"aol.com", "yahoo.com", "yahoodns.net"},
    "icloud.com": {"apple.com", "icloud.com"},
    "me.com": {"apple.com", "icloud.com"},
}


@dataclass(frozen=True)
class Brand:
    key: str                 # compact lowercase name used for matching
    name: str                # how people write it
    domains: frozenset[str]  # registrable domains the brand really uses
    aliases: tuple[str, ...] = ()  # extra names that point at this brand


def _brand(key, name, domains, aliases=()):
    return Brand(key, name, frozenset(domains), tuple(aliases))


BRANDS = (
    _brand("paypal", "PayPal", {"paypal.com", "paypal.me", "paypalobjects.com"}),
    _brand("microsoft", "Microsoft",
           {"microsoft.com", "microsoftonline.com", "office.com", "office365.com",
            "outlook.com", "live.com", "sharepoint.com", "azure.com", "msn.com"},
           ("office365", "microsoft365", "outlook", "onedrive", "sharepoint")),
    _brand("apple", "Apple", {"apple.com", "icloud.com", "me.com"},
           ("appleid", "icloud", "itunes")),
    _brand("amazon", "Amazon",
           {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.fr",
            "amazon.it", "amazon.es", "amazon.co.jp", "amazon.in", "amazon.com.au",
            "amazon.com.br", "amazon.com.mx", "amazon.nl"}),
    _brand("google", "Google", {"google.com", "youtube.com", "gmail.com", "google.co.uk"},
           ("gmail",)),
    _brand("netflix", "Netflix", {"netflix.com"}),
    _brand("docusign", "DocuSign", {"docusign.com", "docusign.net"}),
    _brand("dropbox", "Dropbox", {"dropbox.com", "dropboxmail.com"}),
    _brand("linkedin", "LinkedIn", {"linkedin.com"}),
    _brand("facebook", "Facebook", {"facebook.com", "facebookmail.com", "fb.com", "meta.com"}),
    _brand("instagram", "Instagram", {"instagram.com"}),
    _brand("coinbase", "Coinbase", {"coinbase.com"}),
    _brand("github", "GitHub", {"github.com", "githubusercontent.com"}),
    _brand("adobe", "Adobe", {"adobe.com"}),
    _brand("wellsfargo", "Wells Fargo", {"wellsfargo.com", "wf.com"}),
    _brand("bankofamerica", "Bank of America", {"bankofamerica.com", "bofa.com"}),
    _brand("chase", "Chase", {"chase.com", "jpmorganchase.com"}),
    _brand("fedex", "FedEx", {"fedex.com"}),
    _brand("dhl", "DHL", {"dhl.com", "dhl.de"}),
    _brand("ups", "UPS", {"ups.com"}),
    _brand("usps", "USPS", {"usps.com"}),
    _brand("irs", "IRS", {"irs.gov"}),
)


def normalize_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(normalize_host(host))
    except ValueError:
        return False
    return True


def to_unicode(host: str) -> str:
    """Decode punycode (xn--) labels so look-alike letters become visible."""
    labels = []
    for label in normalize_host(host).split("."):
        if label.startswith("xn--"):
            try:
                label = label[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def to_ascii(host: str) -> str:
    """Encode a Unicode host to its punycode (xn--) form."""
    host = normalize_host(host)
    labels = []
    for label in host.split("."):
        if any(ord(ch) > 127 for ch in label):
            try:
                label = "xn--" + label.encode("punycode").decode("ascii")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def has_non_ascii(text: str) -> bool:
    return any(ord(ch) > 127 for ch in text)


def registrable_domain(host: str) -> str:
    """Best-effort organizational domain: 'a.b.example.co.uk' -> 'example.co.uk'."""
    host = normalize_host(host)
    if not host or is_ip(host):
        return host
    labels = [label for label in host.split(".") if label]
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def subdomain_labels(host: str) -> list[str]:
    host = normalize_host(host)
    if not host or is_ip(host):
        return []
    labels = host.split(".")
    return labels[: len(labels) - len(registrable_domain(host).split("."))]


def tld(host: str) -> str:
    host = normalize_host(host)
    return "" if is_ip(host) else host.rsplit(".", 1)[-1]


def same_organization(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return registrable_domain(to_ascii(a)) == registrable_domain(to_ascii(b))


def is_free_mail(domain: str) -> bool:
    return registrable_domain(domain) in FREE_MAIL_DOMAINS


def brand_owning(host: str) -> Brand | None:
    """The brand that really owns this host, if any."""
    reg = registrable_domain(to_ascii(host))
    for brand in BRANDS:
        if reg in brand.domains:
            return brand
    return None


# --- look-alike detection ----------------------------------------------------

# Letters from other alphabets that render (nearly) like Latin letters.
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ԁ": "d", "ѕ": "s", "һ": "h", "ԛ": "q", "ӏ": "l",
    "к": "k", "м": "m", "т": "t", "в": "b", "н": "h", "ո": "n", "ս": "u",
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "ε": "e", "ι": "i", "κ": "k",
    "τ": "t", "υ": "u", "ϲ": "c", "ı": "i", "ɡ": "g", "ɩ": "i", "ʟ": "l",
}
# Characters that people mistake for each other in Latin text.
_ASCII_LOOKALIKES = {"0": "o", "1": "l", "i": "l", "|": "l", "!": "l", "3": "e",
                     "5": "s", "4": "a", "@": "a", "$": "s", "7": "t"}


def skeleton(text: str) -> str:
    """Collapse look-alike characters so 'pаypa1' and 'paypal' compare equal."""
    text = text.lower()
    text = "".join(_CONFUSABLES.get(ch, ch) for ch in text)
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = "".join(_ASCII_LOOKALIKES.get(ch, ch) for ch in text)
    return text.replace("rn", "m").replace("vv", "w")


def edit_distance(a: str, b: str) -> int:
    """Optimal string alignment distance (counts swapped neighbours as one edit)."""
    rows = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        rows[i][0] = i
    for j in range(len(b) + 1):
        rows[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[-1][-1]


@dataclass(frozen=True)
class Lookalike:
    brand: Brand
    kind: str      # "lookalike", "contains", or "subdomain"
    domain: str    # the registrable domain that is actually used

    def explain(self, host: str) -> str:
        real = " or ".join(sorted(self.brand.domains)[:2])
        if self.kind == "lookalike":
            return (f"'{host}' is spelled to look like {self.brand.name}'s real domain "
                    f"({real}), but it is a different domain: {self.domain}.")
        if self.kind == "subdomain":
            return (f"'{host}' puts the name {self.brand.name} at the front, but the part "
                    f"that decides where it really goes is {self.domain}, which "
                    f"{self.brand.name} does not own.")
        return (f"'{host}' uses the name {self.brand.name}, but {self.domain} is not one "
                f"of {self.brand.name}'s real domains ({real}).")


def _label_match(label: str, brand: Brand) -> str | None:
    key = brand.key
    tokens = [t for t in re.split(r"[-_]", label) if t]
    if label == key or key in tokens:
        return "contains"
    if len(key) >= 6 and key in label:
        return "contains"
    key_skel = skeleton(key)
    for candidate in [label, *tokens]:
        if candidate == key:
            continue
        if skeleton(candidate) == key_skel:
            return "lookalike"
        if len(key) >= 6 and (edit_distance(candidate, key) == 1
                              or edit_distance(skeleton(candidate), key_skel) == 1):
            return "lookalike"
    return None


def brand_lookalike(host: str) -> Lookalike | None:
    """Detect a domain dressed up as a well-known brand it does not belong to."""
    host = normalize_host(host)
    if not host or is_ip(host) or brand_owning(host):
        return None
    uni = to_unicode(host)
    reg = registrable_domain(to_ascii(host))
    main = registrable_domain(uni).split(".")[0]
    for brand in BRANDS:
        kind = _label_match(main, brand)
        if kind:
            return Lookalike(brand, kind, reg)
    for label in subdomain_labels(uni):
        for brand in BRANDS:
            if _label_match(label, brand):
                return Lookalike(brand, "subdomain", reg)
    return None


def brand_in_text(text: str) -> Brand | None:
    """Find a brand named in free text such as a display name."""
    lowered = text.lower()
    compact = re.sub(r"[^a-z0-9]", "", lowered)
    words = set(re.findall(r"[a-z0-9]+", lowered))
    for brand in BRANDS:
        for name in (brand.key, *brand.aliases):
            if len(name) <= 4:
                if name in words:
                    return brand
            elif name in compact:
                return brand
    return None
