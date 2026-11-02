"""URL trick cases. All lexical: nothing here touches the network."""

from phishlens import domains
from phishlens.urls import analyze_text, analyze_url, extract_links, host_from_text, parse_url
from phishlens.verdict import HIGH, LIKELY_PHISHING, LOOKS_SAFE, LOW, MEDIUM, SUSPICIOUS


def has(report, fragment, severity=None):
    return any(fragment.lower() in f.title.lower() and (severity is None or f.severity == severity)
               for f in report.findings)


def test_clean_urls_look_safe():
    for url in ("https://github.com/battlettt/phishlens", "https://www.amazon.co.uk/orders",
                "https://login.microsoftonline.com/common/oauth2", "https://www.wikipedia.org/"):
        report = analyze_url(url)
        assert report.verdict.level == LOOKS_SAFE, (url, report.findings)


def test_at_sign_in_authority():
    report = analyze_url("https://www.paypal.com@evil.example/login")
    assert has(report, "'@' trick", HIGH)
    assert report.host == "evil.example"
    assert report.verdict.level == LIKELY_PHISHING


def test_at_sign_with_fake_password_part():
    report = analyze_url("http://accounts.google.com:secure@198.51.100.5/")
    assert has(report, "'@' trick", HIGH)
    assert report.host == "198.51.100.5"


def test_punycode_homograph():
    fake = domains.to_ascii("pаypal.com")  # Cyrillic "a"
    report = analyze_url(f"https://{fake}/signin")
    assert has(report, "international (look-alike) characters", MEDIUM)
    assert has(report, "imitates PayPal", HIGH)


def test_unicode_host_pasted_directly():
    report = analyze_url("https://аpple.com/")
    assert has(report, "international", MEDIUM)
    assert has(report, "imitates Apple", HIGH)


def test_ip_literal_host():
    report = analyze_url("https://198.51.100.23/account")
    assert has(report, "raw IP address", MEDIUM)


def test_ipv6_literal_host():
    report = analyze_url("http://[2001:db8::1]/")
    assert has(report, "raw IP address", MEDIUM)


def test_obfuscated_ip_formats():
    for url in ("http://3325256727/", "http://0xC6336417/", "http://0306.0063.0144.0027/"):
        report = analyze_url(url)
        assert has(report, "disguised numeric IP", HIGH), url
        assert "198.51.100.23" in report.findings[0].detail.replace("[.]", "."), url


def test_known_shortener():
    for url in ("https://bit.ly/3abcXYZ", "tinyurl.com/y7x8z9", "https://t.co/AbC123"):
        report = analyze_url(url)
        assert has(report, "URL shortener", MEDIUM), url
        assert report.verdict.level == SUSPICIOUS


def test_display_text_does_not_match_href():
    report = analyze_url("http://secure-update.example/x", display_text="https://www.chase.com/login")
    assert has(report, "link text shows one site", HIGH)


def test_display_text_matching_href_is_fine():
    report = analyze_url("https://www.chase.com/login", display_text="chase.com")
    assert not has(report, "link text")


def test_display_text_that_is_not_a_site_is_ignored():
    assert host_from_text("Click here to view") is None
    assert host_from_text("invoice-2291.pdf") is None
    assert host_from_text("Visit www.contoso.com today") == "www.contoso.com"


def test_pasted_html_link_is_analyzed():
    reports = analyze_text('<a href="https://evil.example/login">https://accounts.google.com</a>')
    assert len(reports) == 1
    assert reports[0].display_text == "https://accounts.google.com"
    assert has(reports[0], "link text shows one site", HIGH)


def test_excessive_subdomains_and_brand_decoy():
    report = analyze_url("https://www.paypal.com.account.verify.session-id.example/")
    assert has(report, "unusual number of subdomains", MEDIUM)
    assert has(report, "decoy", HIGH)


def test_suspicious_tld():
    report = analyze_url("https://best-deals.xyz/")
    assert has(report, ".xyz ending", LOW)


def test_lookalike_domains():
    for url, brand in (("https://paypa1.com/", "PayPal"), ("https://rnicrosoft.com/", "Microsoft"),
                       ("https://arnazon.com/", "Amazon"), ("https://netfliix.com/", "Netflix"),
                       ("https://paypal-secure-login.com/", "PayPal"), ("https://g00gle.com/", "Google")):
        report = analyze_url(url)
        assert any(f.severity == HIGH and brand in f.title for f in report.findings), url


def test_brand_on_wrong_tld():
    report = analyze_url("https://paypal.co-verify.ru/")
    assert has(report, "PayPal", HIGH)


def test_plain_http_on_login_path():
    report = analyze_url("http://example-bank.com/secure/login.php")
    assert has(report, "sign-in style page is served over plain http", MEDIUM)
    assert not has(analyze_url("https://example-bank.com/secure/login.php"), "plain http")


def test_unusual_port():
    report = analyze_url("https://example.com:8443/")
    assert has(report, "unusual port (8443)", MEDIUM)
    assert not has(analyze_url("https://example.com:443/"), "unusual port")


def test_dangerous_schemes():
    for url in ("javascript:alert(document.cookie)", "data:text/html;base64,PHNjcmlwdD4="):
        report = analyze_url(url)
        assert report.verdict.level == LIKELY_PHISHING, url


def test_open_redirect_parameter():
    report = analyze_url("https://www.google.com/url?q=https%3A%2F%2Fevil.example%2Flogin")
    assert has(report, "another web address inside it", LOW)


def test_percent_encoded_host():
    report = analyze_url("https://%70%61%79%70%61%6c.evil.example/")
    assert has(report, "percent-encoding", MEDIUM)


def test_backslash_authority_trick():
    parsed = parse_url("https://evil.example\\@paypal.com/")
    assert parsed.host == "evil.example"


def test_already_defanged_input_is_refanged_for_analysis():
    report = analyze_url("hxxps://paypa1[.]com/login")
    assert report.host == "paypa1.com"
    assert has(report, "imitates PayPal", HIGH)


def test_output_is_always_defanged():
    report = analyze_url("https://www.paypal.com@evil.example/login.php")
    assert report.defanged == "hxxps://www[.]paypal[.]com@evil[.]example/login[.]php"
    for f in report.findings:
        assert "://" not in f.detail or "hxxp" in f.detail
        assert "evil.example" not in f.detail


def test_extract_links_from_plain_text():
    text = "Go to https://contoso.com/a. Or (https://bit.ly/x), or www.fabrikam.com/help!"
    urls = [u for u, _ in extract_links(text)]
    assert urls == ["https://contoso.com/a", "https://bit.ly/x", "www.fabrikam.com/help"]


def test_extract_links_from_html_skips_labels_and_mailto():
    html = ('<p>Hi <a href="https://evil.example/">https://www.bank.com</a> '
            '<a href="mailto:a@b.com">mail</a> <a href="#top">top</a></p>')
    assert extract_links(html) == [("https://evil.example/", "https://www.bank.com")]
