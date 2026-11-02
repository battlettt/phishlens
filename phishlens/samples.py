"""Built-in sample emails for --demo. Both are made up; all IPs are documentation ranges."""

PHISHING_SAMPLE = """\
Delivered-To: jordan.lee@example.org
Received: by 2002:a05:6a10:8f0a:b0:4d1:1c2a with SMTP id k10csp912345pxb;
        Mon, 2 Nov 2026 08:14:09 -0800 (PST)
Received: from mail.paypal.com (unknown [198.51.100.77])
        by mx.example.org (Postfix) with ESMTP id 4F2A81C0042
        for <jordan.lee@example.org>; Mon, 2 Nov 2026 16:14:07 +0000 (UTC)
Authentication-Results: mx.example.org;
       spf=fail (mx.example.org: domain of bounce@mailer-notify.top does not designate
        198.51.100.77 as permitted sender) smtp.mailfrom=bounce@mailer-notify.top;
       dkim=none;
       dmarc=none header.from=paypa1-secure.com
Authentication-Results: paypal.com; spf=pass smtp.mailfrom=paypal.com;
       dkim=pass header.d=paypal.com; dmarc=pass header.from=paypal.com
Return-Path: <bounce@mailer-notify.top>
From: "PayPal Security" <service@paypa1-secure.com>
Reply-To: paypal.resolution.team@gmail.com
To: jordan.lee@example.org
Subject: Your account has been limited - action required
Date: Mon, 2 Nov 2026 16:14:02 +0000
Message-ID: <20261102161402.7731@mailer-notify.top>
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body>
<p>We noticed unusual activity on your account. Confirm your details at
<a href="http://198.51.100.23:8080/paypal.com/webscr/login.php">https://www.paypal.com/signin</a>
within 24 hours or your account will be closed.</p>
<p>Or use this short link: <a href="https://bit.ly/3xPpL2k">Restore access</a></p>
</body></html>
"""

LEGITIMATE_SAMPLE = """\
Delivered-To: jordan.lee@example.org
Received: from mx.example.org (mx.example.org [203.0.113.10])
        by mail.example.org with LMTP id 8ZqvEe0vRmd; Mon, 2 Nov 2026 09:02:13 +0000
Received: from o7.sgmail.github.com (o7.sgmail.github.com [203.0.113.45])
        by mx.example.org (Postfix) with ESMTPS id 1B2C3D4E5F
        for <jordan.lee@example.org>; Mon, 2 Nov 2026 09:02:12 +0000 (UTC)
Authentication-Results: mx.example.org;
       dkim=pass header.i=@github.com header.s=pf2023 header.b=Qm9vb2;
       spf=pass (mx.example.org: domain of bounces+1234567@sgmail.github.com designates
        203.0.113.45 as permitted sender) smtp.mailfrom=bounces+1234567@sgmail.github.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=github.com
Return-Path: <bounces+1234567@sgmail.github.com>
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com; s=pf2023;
        h=from:to:subject:date; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=Qm9vb2
From: GitHub <noreply@github.com>
To: jordan.lee@example.org
Subject: [GitHub] A new SSH key was added to your account
Date: Mon, 2 Nov 2026 09:02:10 +0000
Message-ID: <6745f1a2b3c4d_5e6f7a8b9@github.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hey jordan-lee!

A new public key was added to your account. If you did not add it, remove it here:
https://github.com/settings/keys
"""

SAMPLES = (
    ("Sample 1 of 2: a phishing email (made up for this demo)", PHISHING_SAMPLE),
    ("Sample 2 of 2: a legitimate email (made up for this demo)", LEGITIMATE_SAMPLE),
)
