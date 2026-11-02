"""CLI behaviour plus the hard rules: defanged output, no network, nothing stored."""

import io
import os
import re
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

from phishlens.cli import main
from phishlens.defang import defang_text, defang_url
from phishlens.samples import LEGITIMATE_SAMPLE, PHISHING_SAMPLE

ROOT = Path(__file__).resolve().parent.parent
LIVE_LINK = re.compile(r"(?i)\b(?:https?|ftp)://|\bwww\.[a-z]|[a-z0-9-]\.(?:com|net|org|top|ly|example)\b")


def run(argv, stdin_text=""):
    out = io.StringIO()
    code = main(argv, stdin=io.StringIO(stdin_text), stdout=out)
    return code, out.getvalue()


def test_url_mode():
    code, out = run(["--url", "http://paypal.com@198.51.100.5:8080/login"])
    assert code == 0
    assert "VERDICT: LIKELY PHISHING" in out
    assert "hxxp://paypal[.]com@198[.]51[.]100[.]5:8080/login" in out
    assert "What to do:" in out


def test_url_mode_accepts_multiple_urls_and_html():
    code, out = run(["--url", "https://github.com/", '<a href="https://evil.example/">paypal.com</a>'])
    assert code == 0
    assert out.count("VERDICT:") == 2
    assert "LOOKS SAFE" in out and "LIKELY PHISHING" in out


def test_headers_from_file():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "headers.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(PHISHING_SAMPLE)
        code, out = run(["--headers", path])
    assert code == 0
    assert "VERDICT: LIKELY PHISHING" in out
    for name in ("SPF:", "DKIM:", "DMARC:"):
        assert name in out


def test_headers_from_stdin():
    code, out = run(["--headers"], stdin_text=LEGITIMATE_SAMPLE)
    assert code == 0
    assert "VERDICT: LOOKS SAFE" in out
    code, out = run(["--headers", "-"], stdin_text=LEGITIMATE_SAMPLE)
    assert "VERDICT: LOOKS SAFE" in out


def test_non_header_input_is_a_usage_error():
    code, out = run(["--headers"], stdin_text="hello there")
    assert code == 2 and out == ""


def test_demo_shows_both_labeled_samples():
    code, out = run(["--demo"])
    assert code == 0
    assert "Sample 1 of 2: a phishing email" in out
    assert "Sample 2 of 2: a legitimate email" in out
    assert "VERDICT: LIKELY PHISHING" in out and "VERDICT: LOOKS SAFE" in out


def test_no_output_contains_a_clickable_link():
    outputs = [run(["--demo"])[1],
               run(["--url", "https://www.paypal.com.verify.example.top/login?next=http://x.org"])[1],
               run(["--url", '<a href="http://198.51.100.1/">www.bank.com</a>'])[1]]
    for out in outputs:
        assert not LIVE_LINK.search(out), LIVE_LINK.search(out).group(0)


def test_defang_helpers():
    assert defang_url("https://a.b.com/x.php") == "hxxps://a[.]b[.]com/x[.]php"
    assert defang_url("mailto:x@y.com") == "mailto[:]x@y[.]com"
    assert defang_url(defang_url("http://a.com")) == "hxxp://a[.]com"  # idempotent
    assert defang_text("see http://evil.com or 10.0.0.1") == "see hxxp://evil[.]com or 10[.]0[.]0[.]1"


def test_analysis_makes_no_network_connections():
    def refuse(*args, **kwargs):
        raise AssertionError("PhishLens tried to open a network connection")

    saved = (socket.socket.connect, socket.create_connection, socket.getaddrinfo)
    socket.socket.connect, socket.create_connection, socket.getaddrinfo = refuse, refuse, refuse
    try:
        run(["--demo"])
        run(["--url", "https://bit.ly/abc", "http://3325256727/", "https://xn--pypal-4ve.com/"])
    finally:
        socket.socket.connect, socket.create_connection, socket.getaddrinfo = saved


def test_nothing_is_written_to_disk():
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run([sys.executable, "-m", "phishlens", "--headers"], input=PHISHING_SAMPLE,
                                capture_output=True, text=True, cwd=tmp, env=env, timeout=60)
        assert result.returncode == 0, result.stderr
        assert "LIKELY PHISHING" in result.stdout
        assert os.listdir(tmp) == []


def test_source_has_no_network_mail_or_storage_code():
    banned = re.compile(
        r"^\s*(?:import|from)\s+(?:socket|ssl|smtplib|imaplib|poplib|ftplib|logging|sqlite3|"
        r"shelve|pickle|requests|urllib\.request|http\.client)\b"
        r"|\bopen\([^)]*[\"'][wax]b?\+?[\"']|\.write_(?:text|bytes)\(|tempfile",
        re.M)
    for path in (ROOT / "phishlens").glob("*.py"):
        match = banned.search(path.read_text(encoding="utf-8"))
        assert not match, f"{path.name} contains {match.group(0)!r}"


def test_example_files_match_builtin_samples():
    examples = ROOT / "examples"
    assert (examples / "phishing-headers.txt").read_text(encoding="utf-8") == PHISHING_SAMPLE
    assert (examples / "legitimate-headers.txt").read_text(encoding="utf-8") == LEGITIMATE_SAMPLE


def test_demo_page_is_labeled_and_has_no_live_links_except_the_repo():
    page = (ROOT / "demo" / "index.html").read_text(encoding="utf-8")
    assert "static showcase, not a live analyzer" in page
    assert "Sample 1 of 2" in page and "Sample 2 of 2" in page
    assert "LIKELY PHISHING" in page and "LOOKS SAFE" in page
    links = set(re.findall(r"(?i)\b(?:https?|ftp)://[^\s\"'<>]+", page))
    assert links == {"https://github.com/battlettt/phishlens"}
    assert "<script" not in page.lower()
