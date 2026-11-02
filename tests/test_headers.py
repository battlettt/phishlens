"""Header spoofing cases."""

from phishlens import domains
from phishlens.headers import (NotHeadersError, analyze_headers, parse_authentication_results,
                               parse_received)
from phishlens.samples import LEGITIMATE_SAMPLE, PHISHING_SAMPLE
from phishlens.verdict import HIGH, INFO, LIKELY_PHISHING, LOOKS_SAFE, LOW, MEDIUM, SUSPICIOUS

GOOD_AUTH = ("Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=bounce@{d}; "
             "dkim=pass header.d={d}; dmarc=pass header.from={d}")


def message(from_="Alex Wu <alex@contoso.com>", auth=GOOD_AUTH.format(d="contoso.com"),
            return_path="<bounce@contoso.com>",
            received="from mail.contoso.com (mail.contoso.com [203.0.113.5]) by mx.example.org; "
                     "Mon, 2 Nov 2026 10:00:00 +0000",
            extra="", body=""):
    lines = []
    if received:
        lines.append(f"Received: {received}")
    if auth:
        lines.append(auth)
    if return_path:
        lines.append(f"Return-Path: {return_path}")
    if from_:
        lines.append(f"From: {from_}")
    lines += ["To: jordan@example.org", "Subject: Hello", "Message-ID: <abc123@contoso.com>"]
    if extra:
        lines.append(extra)
    text = "\n".join(lines) + "\n"
    return text + ("\n" + body if body else "")


def titles(report, severity=None):
    return [f.title for f in report.findings if severity is None or f.severity == severity]


def has(report, fragment, severity=None):
    return any(fragment.lower() in t.lower() for t in titles(report, severity))


# --- baseline ---------------------------------------------------------------------

def test_clean_authenticated_message_looks_safe():
    report = analyze_headers(message())
    assert report.verdict.level == LOOKS_SAFE
    assert report.verdict.reasons == ()
    assert report.auth["SPF"].status == "PASS (aligned)"
    assert report.auth["DKIM"].status == "PASS (aligned)"
    assert report.auth["DMARC"].status == "PASS"


def test_demo_samples_get_expected_verdicts():
    assert analyze_headers(PHISHING_SAMPLE).verdict.level == LIKELY_PHISHING
    assert analyze_headers(LEGITIMATE_SAMPLE).verdict.level == LOOKS_SAFE


def test_text_without_headers_is_rejected():
    try:
        analyze_headers("just some words, nothing like an email header")
    except NotHeadersError:
        return
    raise AssertionError("expected NotHeadersError")


# --- From / Return-Path / Reply-To ----------------------------------------------------

def test_from_and_return_path_mismatch_without_authentication():
    report = analyze_headers(message(auth="", return_path="<x@bulk-sender.biz>"))
    assert has(report, "From and Return-Path domains do not match", MEDIUM)
    assert report.verdict.level in (SUSPICIOUS, LIKELY_PHISHING)


def test_return_path_mismatch_is_only_a_note_when_dmarc_passes():
    auth = ("Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=b@esp-mail.net; "
            "dkim=pass header.d=contoso.com; dmarc=pass header.from=contoso.com")
    report = analyze_headers(message(auth=auth, return_path="<b@esp-mail.net>"))
    assert has(report, "Return-Path domain differs", INFO)
    assert report.auth["SPF"].status == "PASS (not aligned)"
    assert report.verdict.level == LOOKS_SAFE


def test_reply_to_differs_from_from():
    report = analyze_headers(message(extra="Reply-To: payments.desk@gmail.com"))
    assert has(report, "Replies would go to a different address", MEDIUM)
    detail = next(f.detail for f in report.findings if "Replies" in f.title)
    assert "free personal mailbox" in detail
    assert "gmail[.]com" in detail


def test_reply_to_same_organization_is_fine():
    report = analyze_headers(message(extra="Reply-To: help@support.contoso.com"))
    assert not has(report, "Replies would go")


# --- display-name spoofing ------------------------------------------------------------

def test_brand_display_name_with_unrelated_address():
    report = analyze_headers(message(from_='"PayPal Service" <alerts@account-notice.net>',
                                     auth="", return_path="<alerts@account-notice.net>"))
    assert has(report, "claims to be PayPal", HIGH)
    assert report.verdict.level == LIKELY_PHISHING


def test_brand_display_name_from_free_mail_is_spoofing():
    report = analyze_headers(message(from_="Google Accounts <google.accounts.team@gmail.com>",
                                     auth=GOOD_AUTH.format(d="gmail.com"),
                                     return_path="<google.accounts.team@gmail.com>"))
    assert has(report, "claims to be Google", HIGH)


def test_brand_display_name_from_real_brand_domain_is_fine():
    report = analyze_headers(message(from_="PayPal <service@paypal.com>",
                                     auth=GOOD_AUTH.format(d="paypal.com"),
                                     return_path="<bounce@paypal.com>",
                                     received="from mx1.paypal.com (mx1.paypal.com [203.0.113.9]) "
                                              "by mx.example.org; Mon, 2 Nov 2026 10:00:00 +0000"))
    assert not has(report, "claims to be")
    assert report.verdict.level == LOOKS_SAFE


def test_display_name_containing_a_different_address():
    report = analyze_headers(message(from_='"security@microsoft.com" <ms-alert@notify-center.ru>'))
    assert has(report, "name shows a different email address", HIGH)


def test_encoded_display_name_is_decoded_before_checking():
    # "=?utf-8?B?UGF5UGFs?=" is base64 for "PayPal".
    report = analyze_headers(message(from_="=?utf-8?B?UGF5UGFs?= <help@random-host.io>"))
    assert report.from_addr.display == "PayPal"
    assert has(report, "claims to be PayPal", HIGH)


def test_official_role_name_from_free_mailbox():
    report = analyze_headers(message(from_="IT Support Desk <it.support.desk@outlook.com>",
                                     auth=GOOD_AUTH.format(d="outlook.com"),
                                     return_path="<it.support.desk@outlook.com>"))
    assert has(report, "official-sounding name", MEDIUM)


# --- look-alike and IDN domains --------------------------------------------------------

def test_lookalike_from_domain_with_digit_substitution():
    report = analyze_headers(message(from_="Billing <billing@paypa1.com>",
                                     auth=GOOD_AUTH.format(d="paypa1.com"),
                                     return_path="<b@paypa1.com>"))
    assert has(report, "From domain imitates PayPal", HIGH)
    assert report.verdict.level == LIKELY_PHISHING


def test_lookalike_from_domain_with_rn_for_m():
    report = analyze_headers(message(from_="Team <team@rnicrosoft.com>"))
    assert has(report, "imitates Microsoft", HIGH)


def test_idn_homograph_from_domain():
    fake = domains.to_ascii("аpple.com")  # Cyrillic "a" + "pple"
    assert fake.startswith("xn--")
    report = analyze_headers(message(from_=f"Apple <id@{fake}>", auth=GOOD_AUTH.format(d=fake),
                                     return_path=f"<b@{fake}>"))
    assert has(report, "international (look-alike) characters", MEDIUM)
    assert has(report, "imitates Apple", HIGH)


def test_lookalike_reply_to_domain():
    report = analyze_headers(message(extra="Reply-To: refunds@amaz0n-support.com"))
    assert has(report, "Reply-To domain imitates Amazon", HIGH)


# --- Received chain --------------------------------------------------------------------

def test_first_hop_not_matching_sender_domain():
    report = analyze_headers(message(
        auth="", received="from vps-2291.cheap-hosting.example (vps-2291.cheap-hosting.example "
                          "[198.51.100.9]) by mx.example.org; Mon, 2 Nov 2026 10:00:00 +0000"))
    assert has(report, "first server in the delivery chain does not belong", LOW)


def test_first_hop_mismatch_is_a_note_when_authenticated():
    report = analyze_headers(message(
        received="from o1.mailservice.example (o1.mailservice.example [198.51.100.9]) "
                 "by mx.example.org; Mon, 2 Nov 2026 10:00:00 +0000"))
    assert has(report, "first server in the delivery chain does not belong", INFO)
    assert report.verdict.level == LOOKS_SAFE


def test_first_hop_claims_sender_name_but_real_name_differs():
    report = analyze_headers(message(
        auth="", received="from mail.contoso.com (host-77.botnet.example [198.51.100.77]) "
                          "by mx.example.org; Mon, 2 Nov 2026 10:00:00 +0000"))
    assert has(report, "introduced itself with the sender's name", MEDIUM)


def test_oldest_hop_is_used_and_private_hops_are_skipped():
    text = ("Received: from mx.example.org (mx.example.org [203.0.113.1]) by mail.example.org; "
            "Mon, 2 Nov 2026 10:00:05 +0000\n"
            "Received: from mail.contoso.com (mail.contoso.com [203.0.113.5]) by mx.example.org; "
            "Mon, 2 Nov 2026 10:00:03 +0000\n"
            "Received: from laptop (unknown [192.168.1.20]) by mail.contoso.com; "
            "Mon, 2 Nov 2026 10:00:01 +0000\n"
            + message(received=""))
    report = analyze_headers(text)
    assert report.first_hop.helo == "mail.contoso.com"
    assert not has(report, "first server")


def test_received_timestamps_out_of_order():
    text = ("Received: from mx.example.org (mx.example.org [203.0.113.1]) by mail.example.org; "
            "Mon, 2 Nov 2026 08:00:00 +0000\n"
            + message(received="from mail.contoso.com (mail.contoso.com [203.0.113.5]) "
                               "by mx.example.org; Mon, 2 Nov 2026 10:00:00 +0000"))
    assert has(analyze_headers(text), "timestamps are out of order", LOW)


def test_parse_received_formats():
    hop = parse_received("from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])\n"
                         "        by mx.google.com with SMTPS; Mon, 02 Nov 2026 10:00:01 -0800 (PST)")
    assert (hop.helo, hop.rdns, hop.ip, hop.by) == (
        "mail-sor-f41.google.com", "mail-sor-f41.google.com", "209.85.220.41", "mx.google.com")
    assert hop.date is not None
    exim = parse_received("from [198.51.100.3] (helo=smtp.contoso.com) by mx.example.org")
    assert exim.helo == "smtp.contoso.com" and exim.ip == "198.51.100.3"


# --- authentication --------------------------------------------------------------------

def test_missing_authentication_results():
    report = analyze_headers(message(auth=""))
    assert has(report, "No authentication results", MEDIUM)
    for name in ("SPF", "DKIM", "DMARC"):
        assert report.auth[name].status == "NOT REPORTED"


def test_all_authentication_failing():
    auth = ("Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=contoso.com; "
            "dkim=fail header.d=contoso.com; dmarc=fail (p=REJECT) header.from=contoso.com")
    report = analyze_headers(message(auth=auth))
    assert report.auth["SPF"].status == "FAIL"
    assert report.auth["DKIM"].status == "FAIL"
    assert report.auth["DMARC"].status == "FAIL"
    assert has(report, "SPF failed", MEDIUM)
    assert has(report, "DKIM signature failed", MEDIUM)
    assert has(report, "DMARC failed", HIGH)
    detail = next(f.detail for f in report.findings if "DMARC failed" in f.title)
    assert "p=reject" in detail and "rejected" in detail
    assert report.verdict.level == LIKELY_PHISHING


def test_spf_fail_is_minor_when_dkim_keeps_dmarc_passing():
    auth = ("Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=contoso.com; "
            "dkim=pass header.d=contoso.com; dmarc=pass header.from=contoso.com")
    report = analyze_headers(message(auth=auth))
    assert has(report, "SPF failed", LOW)
    assert report.verdict.level == LOOKS_SAFE


def test_spf_softfail():
    auth = "Authentication-Results: mx.example.org; spf=softfail smtp.mailfrom=contoso.com"
    report = analyze_headers(message(auth=auth))
    assert report.auth["SPF"].status == "SOFTFAIL"
    assert has(report, "SPF soft-failed", LOW)


def test_alignment_is_reported_separately_for_each_check():
    auth = ("Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=bounce@esp.example; "
            "dkim=pass header.d=esp.example")
    report = analyze_headers(message(auth=auth, return_path="<bounce@esp.example>"))
    assert report.auth["SPF"].status == "PASS (not aligned)"
    assert report.auth["DKIM"].status == "PASS (not aligned)"
    assert report.auth["DMARC"].status == "NOT REPORTED (no alignment)"
    assert has(report, "Nothing proves this email really came from", MEDIUM)


def test_dmarc_computed_from_aligned_dkim_when_not_reported():
    auth = "Authentication-Results: mx.example.org; dkim=pass header.i=@mail.contoso.com"
    report = analyze_headers(message(auth=auth))
    assert report.auth["DKIM"].status == "PASS (aligned)"
    assert report.auth["DMARC"].status == "NOT REPORTED (alignment OK)"


def test_dmarc_pass_for_a_different_domain_is_a_contradiction():
    auth = ("Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=evil.example; "
            "dkim=pass header.d=evil.example; dmarc=pass header.from=evil.example")
    report = analyze_headers(message(auth=auth))
    assert has(report, "DMARC pass is for a different domain", HIGH)


def test_dmarc_pass_without_any_aligned_pass_is_a_contradiction():
    auth = ("Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=contoso.com; "
            "dkim=none; dmarc=pass header.from=contoso.com")
    report = analyze_headers(message(auth=auth))
    assert has(report, "DMARC says pass, but SPF and DKIM do not back it up", MEDIUM)


def test_fake_lower_authentication_results_contradiction():
    auth = ("Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=contoso.com; "
            "dkim=none; dmarc=fail header.from=contoso.com\n"
            "Authentication-Results: contoso.com; spf=pass; dkim=pass; dmarc=pass")
    report = analyze_headers(message(auth=auth))
    assert has(report, "Authentication results contradict each other", MEDIUM)
    assert report.auth["SPF"].status == "FAIL"  # the top (receiving server) result wins


def test_received_spf_disagrees_with_authentication_results():
    auth = (GOOD_AUTH.format(d="contoso.com")
            + "\nReceived-SPF: fail (mx.example.org: domain of contoso.com does not designate)")
    report = analyze_headers(message(auth=auth))
    assert has(report, "SPF results in different headers disagree", MEDIUM)


def test_parse_authentication_results_with_comments_and_no_authserv_id():
    results = parse_authentication_results(
        "spf=pass (sender IP is 40.107.22.101; trusted) smtp.mailfrom=contoso.com; "
        "dkim=pass (signature was verified) header.d=contoso.com;dmarc=pass action=none "
        "header.from=contoso.com;compauth=pass reason=100")
    by_method = {r.method: r for r in results}
    assert by_method["spf"].result == "pass"
    assert by_method["spf"].props["smtp.mailfrom"] == "contoso.com"
    assert by_method["dkim"].props["header.d"] == "contoso.com"
    assert by_method["dmarc"].props["header.from"] == "contoso.com"


# --- Message-ID, List-Unsubscribe, body links --------------------------------------------

def test_missing_message_id():
    text = message().replace("Message-ID: <abc123@contoso.com>\n", "")
    assert has(analyze_headers(text), "no Message-ID", LOW)


def test_list_unsubscribe_is_parsed():
    report = analyze_headers(message(extra="List-Unsubscribe: <https://contoso.com/u?id=1>, "
                                           "<mailto:unsub@contoso.com>"))
    assert report.list_unsubscribe == ["https://contoso.com/u?id=1", "mailto:unsub@contoso.com"]
    assert has(report, "List-Unsubscribe", INFO)


def test_suspicious_unsubscribe_link_is_flagged():
    report = analyze_headers(message(extra="List-Unsubscribe: <http://198.51.100.4:8081/u>"))
    assert has(report, "unsubscribe link is suspicious")


def test_body_links_are_extracted_and_analyzed():
    body = ('<html><body><a href="http://paypal.com.secure-check.top/login">'
            "https://www.paypal.com</a> or https://bit.ly/abc123.</body></html>")
    report = analyze_headers(message(extra="Content-Type: text/html", body=body))
    urls = [link.url for link in report.links]
    assert "http://paypal.com.secure-check.top/login" in urls
    assert "https://bit.ly/abc123" in urls
    assert has(report, "link in the message is dangerous", HIGH)
    assert report.verdict.level == LIKELY_PHISHING


def test_tracking_link_in_authenticated_newsletter_is_not_suspicious():
    body = ('<a href="https://contoso.us4.list-manage.com/track/click?u=1">'
            "www.contoso.com/sale</a>")
    report = analyze_headers(message(extra="Content-Type: text/html", body=body))
    assert has(report, "click-tracking service", INFO)
    assert report.verdict.level == LOOKS_SAFE
