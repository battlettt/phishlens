# PhishLens

Paste an email's headers or a suspicious link and get a plain-English verdict:
**LOOKS SAFE**, **SUSPICIOUS**, or **LIKELY PHISHING**. Each verdict lists the
specific reasons and says what to do.

## What it solves

Phishing emails often look perfect in the inbox. The giveaways are in places most
people never look: the hidden envelope sender, the authentication results the
receiving server recorded, the first server in the delivery chain, or a link whose
text says one site while the link goes to another. PhishLens reads those details
and explains them in everyday language.

## Safety guarantees

- **Pasted text only.** PhishLens never opens a mailbox, never sends mail, and
  never connects to a mail server.
- **No network at all.** It never fetches a URL and makes no DNS lookups. All
  checks are lexical, on the text you paste.
- **Nothing is stored.** Input is analyzed in memory. There are no logs, history,
  cache, or output files.
- **Defanged output.** Every URL and domain in a report is written as
  `hxxps://example[.]com`, so nothing in the output is clickable.

The test suite enforces these rules: it blocks sockets during analysis, checks that
nothing is written to disk, and scans every report for live links.

## How to run it

Needs Python 3.11 or newer. Analysis uses only the standard library.

```sh
python -m phishlens --headers headers.txt        # headers saved to a file
python -m phishlens --headers < headers.txt      # or piped on stdin
pbpaste | python -m phishlens --headers          # macOS clipboard
python -m phishlens --url "https://bit.ly/3abc"  # one or more links
python -m phishlens --url '<a href="https://evil.example/">paypal.com</a>'  # pasted HTML link
python -m phishlens --demo                       # built-in phishing + legitimate samples
```

Sample header files are in `examples/`. To get headers from your own email, use
"Show original" (Gmail), "View message source" (Outlook), or "View > Message >
All Headers" (Apple Mail), then copy everything. If you also paste the body,
PhishLens pulls out the links and checks each one.

Tests:

```sh
pip install pytest   # the only extra, for tests only
python -m pytest
```

## How it works

### Headers (`phishlens/headers.py`)

PhishLens parses From, Reply-To, Return-Path, the Received chain,
Authentication-Results (plus Received-SPF and DKIM-Signature), Message-ID, and
List-Unsubscribe. Then it checks for:

| Check | Example |
|---|---|
| From vs Return-Path mismatch | From `paypal-alerts.com`, bounces to `mailer-xyz.top` |
| Reply-To differs from From | replies go to a free Gmail address |
| Display-name spoofing | `"PayPal Security" <x@random.net>`, an address inside the name, or "IT Support" from a free mailbox |
| Look-alike and IDN domains | `paypa1.com`, `rnicrosoft.com`, Cyrillic `аpple.com` (`xn--pple-43d.com`) |
| Received chain anomalies | the first server isn't the sender's, its claimed name differs from its real name, or the timestamps run backwards |
| Missing or failing authentication | no results, SPF fail or softfail, DKIM fail, DMARC fail |
| Authentication contradictions | a lower, fake "pass" header, a DMARC pass for a different domain, a DMARC pass with no aligned SPF or DKIM, or Received-SPF disagreeing with the results |

**SPF, DKIM, and DMARC are reported separately.** Each one shows its result and
whether it is *aligned*, meaning it matches the From domain (relaxed alignment, by
organizational domain). If no DMARC result was recorded, PhishLens works out
alignment from SPF and DKIM. Everything comes from the Authentication-Results
that the receiving server already wrote. Nothing is looked up again.

### URLs (`phishlens/urls.py`)

These checks are lexical only, with no fetching and no DNS: punycode and IDN
homographs, `@` in the authority (`https://paypal.com@evil.example`), IP-literal
hosts (including decimal, hex, and octal disguises), known URL shorteners, link
text that names a different site than the href, excessive subdomains, a brand used
as a decoy subdomain, suspicious TLDs, look-alike domains, plain http on sign-in
style paths, unusual ports, `javascript:` and `data:` links, percent-encoded
hosts, and redirect parameters.

### Verdicts (`phishlens/verdict.py`)

Each finding carries a severity and a plain-English explanation. Any HIGH finding,
or enough smaller ones combined, gives LIKELY PHISHING. A couple of warning signs
gives SUSPICIOUS. Otherwise the verdict is LOOKS SAFE. Context that is normal in
legitimate mail is listed under "Also noted" and does not count against the
message. For example, a newsletter whose Return-Path belongs to its email service
but which still passes DMARC.

## Examples

```text
$ python -m phishlens --url "http://paypal.com.account-verify.top/signin"
PhishLens: link analysis
========================

Link:         hxxp://paypal[.]com[.]account-verify[.]top/signin
Real site:    paypal[.]com[.]account-verify[.]top

VERDICT: LIKELY PHISHING
This link shows strong signs of phishing. It is built to look like somewhere
you trust while really going somewhere else, or it hides where it goes.

Why (most serious first):
  1. [HIGH] PayPal's name is used as a decoy at the front of the address
     'paypal[.]com[.]account-verify[.]top' puts the name PayPal at the front,
     but the part that decides where it really goes is account-verify[.]top,
     which PayPal does not own.
  2. [MEDIUM] A sign-in style page is served over plain http
     ...
  3. [LOW] The site uses the .top ending, which is often abused
     ...

What to do:
  - Do not open this link.
  ...
```

```text
$ python -m phishlens --headers examples/legitimate-headers.txt
VERDICT: LOOKS SAFE
...
Authentication checks (from the pasted Authentication-Results):
  SPF:   PASS (aligned)
         The sending server was authorized to send mail for
         sgmail[.]github[.]com, which matches the From domain (github[.]com).
  DKIM:  PASS (aligned)
         ...
  DMARC: PASS
         The From domain (github[.]com) is authenticated: SPF or DKIM passed
         for a matching domain. The domain's policy is p=reject.
```

Run `python -m phishlens --demo` to see the full phishing report. It catches a
PayPal display-name spoof, a look-alike domain, an SPF failure, a fake "pass"
header, a Gmail Reply-To, and a link whose text and real destination differ.

A static walkthrough of both samples is in [`demo/index.html`](demo/index.html).

## Limitations

- PhishLens judges only what you paste. A perfectly authenticated email from a
  domain the attacker owns can still be a scam. The look-alike checks help, but
  they cover a built-in list of commonly impersonated brands.
- Organizational domains come from a small built-in suffix list, not the full
  Public Suffix List, because PhishLens downloads nothing.
- Shortened links can't be expanded without visiting them, so they are flagged
  rather than followed.

## Project layout

```text
phishlens/
  __main__.py   entry point for python -m phishlens
  cli.py        argument parsing, input reading
  headers.py    header parsing, SPF/DKIM/DMARC, spoofing checks
  urls.py       lexical URL checks, link extraction from text and HTML
  domains.py    registrable domains, punycode, brand look-alikes
  verdict.py    findings -> verdict and advice
  report.py     plain-text rendering (always defanged)
  defang.py     hxxp / [.] defanging
  samples.py    built-in demo emails
tests/          header spoofing, URL trick, and CLI/safety tests
examples/       sample header files
demo/index.html static showcase with precomputed verdicts
```
