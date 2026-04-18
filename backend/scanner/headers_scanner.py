import httpx

from models import Finding, Severity, Category

HEADER_CHECKS = [
    (
        "strict-transport-security",
        "headers_no_hsts",
        "HSTS header missing",
        "The Strict-Transport-Security header is not set. Browsers won't enforce HTTPS on repeat visits, leaving users vulnerable to SSL-stripping attacks.",
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to your server responses.",
    ),
    (
        "x-frame-options",
        "headers_no_xframe",
        "Clickjacking protection missing",
        "The X-Frame-Options header is not set. Your site can be embedded in an iframe on a malicious page to trick users into clicking hidden elements.",
        "Add `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN` to your server responses.",
    ),
    (
        "x-content-type-options",
        "headers_no_xcto",
        "MIME sniffing protection missing",
        "The X-Content-Type-Options header is not set. Browsers may interpret files as a different MIME type, enabling certain injection attacks.",
        "Add `X-Content-Type-Options: nosniff` to your server responses.",
    ),
    (
        "content-security-policy",
        "headers_no_csp",
        "Content Security Policy missing",
        "No Content-Security-Policy header is set. Without CSP, injected scripts can execute freely in users' browsers.",
        "Add a Content-Security-Policy header. Start with `default-src 'self'` and expand as needed.",
    ),
]


async def scan(host_url: str) -> list[Finding]:
    base = host_url.rstrip("/")
    findings: list[Finding] = []

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=5) as client:
            resp = await client.get(base)
            headers = resp.headers

            for header_name, finding_id, title, description, fix in HEADER_CHECKS:
                if header_name not in headers:
                    findings.append(Finding(
                        id=finding_id,
                        severity=Severity.MEDIUM,
                        title=title,
                        description=description,
                        affected=base,
                        fix=fix,
                        category=Category.HEADERS,
                    ))

    except httpx.RequestError:
        return []

    if not findings:
        findings.append(Finding(
            id="headers_all_present",
            severity=Severity.PASS,
            title="Security headers in place",
            description="HSTS, X-Frame-Options, X-Content-Type-Options, and CSP headers are all set.",
            affected=base,
            fix="No action needed.",
            category=Category.HEADERS,
        ))

    return findings
