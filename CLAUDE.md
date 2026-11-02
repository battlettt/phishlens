# PhishLens

Python CLI that analyzes pasted email headers and URLs and gives plain-English
verdicts: LOOKS SAFE, SUSPICIOUS, or LIKELY PHISHING, with reasons and advice.

## Run
- `python -m phishlens --headers headers.txt` (or `--headers` / `--headers -` for stdin)
- `python -m phishlens --url <url> [<url> ...]` (also accepts a pasted `<a href>` link)
- `python -m phishlens --demo` (built-in phishing and legitimate samples)
- Sample inputs: `examples/phishing-headers.txt`, `examples/legitimate-headers.txt`

## Test
- `python -m pytest` (pytest is the only non-stdlib tool, for tests only)

## Hard rules (tests enforce these)
- Pasted text only: never open a mailbox, send mail, or contact a mail server.
- No network during analysis: no fetching, no DNS. URL checks are lexical.
- Nothing about analyzed content is stored: no logs, files, cache, or history.
- Every URL and domain in output is defanged (`hxxp`, `[.]`). `report.py` runs
  `defang_text` over each finished report as a safety net.
- SPF, DKIM, and DMARC (with alignment) are reported separately, from the pasted
  Authentication-Results and the From and Return-Path domains.
- Verdicts explain reasons in plain English, not just a score.

## Layout
- `phishlens/headers.py`: header parsing, auth checks, spoofing and Received checks
- `phishlens/urls.py`: lexical URL checks; link extraction from text and HTML
- `phishlens/domains.py`: registrable domains, punycode, brand look-alikes
- `phishlens/verdict.py`: `Finding` (severity, title, detail) to `Verdict`
- `phishlens/report.py`: text rendering; `phishlens/cli.py`: argparse entry
- `phishlens/samples.py`: demo emails (must match the files in `examples/`)
- `demo/index.html`: static showcase with precomputed verdicts (not a live tool)
- `tests/`: header spoofing, URL tricks, CLI and safety-rule tests

## Conventions
- Python 3.11+, standard library only.
- Scoring: any HIGH finding, or 6+ points, gives LIKELY PHISHING; 2+ points
  gives SUSPICIOUS (low=1, medium=2, high=4). INFO findings are notes that
  don't count.
- New checks add a `Finding` with a plain-English title and detail, run their
  domains through `defang_domain` and URLs through `defang_url`, and get a test.
- Keep normal patterns in legitimate mail (email services, click trackers) as
  INFO when DMARC passes, so real newsletters still LOOK SAFE.
- If you change `samples.py`, regenerate `examples/` and `demo/index.html`.

## Pointers
- README.md: full usage, how each check works, examples, limitations.
