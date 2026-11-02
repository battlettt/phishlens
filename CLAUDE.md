# PhishLens

Email header and URL analyzer that gives plain-English verdicts.
Paste headers or a URL; it never opens a mailbox and never sends mail.

## Run
- `python -m phishlens --headers headers.txt`
- `python -m phishlens --url <url>`
- `python -m phishlens --demo`

## Test
- `python -m pytest`

## Conventions
- Python 3.11+, standard library only for analysis; pytest for tests.
- Defang URLs in output (hxxp) and never fetch a suspicious URL.
- Verdicts explain the reason in plain English, not just a score.
- Pasted content is analyzed in memory only; nothing is stored.
- SPF, DKIM, and DMARC alignment are checked and reported separately.

## Pointers
- README.md: full usage and examples.
- tests/: header spoofing and URL trick cases.
