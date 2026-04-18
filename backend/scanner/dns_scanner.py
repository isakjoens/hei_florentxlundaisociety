import asyncio
from urllib.parse import urlparse

import dns.resolver
import dns.exception

from models import Finding, Severity, Category


async def _resolve_txt(domain: str) -> list[str]:
    """Return all TXT record strings for domain, or [] on any error."""
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(domain, "TXT", lifetime=5)
        )
        return [rdata.to_text().strip('"') for rdata in answers]
    except (dns.exception.DNSException, OSError):
        return []


async def scan(host_url: str) -> list[Finding]:
    parsed = urlparse(host_url)
    domain = parsed.hostname or ""

    # Skip localhost and bare IPs — DNS checks don't apply
    if not domain or domain == "localhost" or _is_ip(domain):
        return [Finding(
            id="dns_skipped",
            severity=Severity.PASS,
            title="DNS checks skipped (localhost / IP)",
            description="Email security checks require a real domain name.",
            affected=domain or host_url,
            fix="No action needed for local targets.",
            category=Category.DNS,
        )]

    findings: list[Finding] = []

    # --- SPF ---
    txt_records = await _resolve_txt(domain)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    if not spf_records:
        findings.append(Finding(
            id="dns_no_spf",
            severity=Severity.HIGH,
            title="No SPF record — email spoofing possible",
            description=(
                f"{domain} has no SPF (Sender Policy Framework) DNS record. "
                "Anyone can send emails that appear to come from your domain."
            ),
            affected=domain,
            fix=(
                "Add a TXT record to your DNS: `v=spf1 include:your-mail-provider.com ~all`. "
                "Replace `your-mail-provider.com` with your actual email provider."
            ),
            category=Category.DNS,
        ))
    else:
        findings.append(Finding(
            id="dns_spf_present",
            severity=Severity.PASS,
            title="SPF record present",
            description=f"SPF record found for {domain}: {spf_records[0][:80]}",
            affected=domain,
            fix="No action needed.",
            category=Category.DNS,
        ))

    # --- DMARC ---
    dmarc_records = await _resolve_txt(f"_dmarc.{domain}")
    dmarc_found = [r for r in dmarc_records if r.startswith("v=DMARC1")]

    if not dmarc_found:
        findings.append(Finding(
            id="dns_no_dmarc",
            severity=Severity.HIGH,
            title="No DMARC record — phishing risk",
            description=(
                f"{domain} has no DMARC policy. Without DMARC, spoofed emails from your "
                "domain may be delivered to recipients and you have no visibility into abuse."
            ),
            affected=f"_dmarc.{domain}",
            fix=(
                "Add a TXT record: `_dmarc.{domain}` → `v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}`. "
                "Start with `p=none` to monitor before enforcing."
            ),
            category=Category.DNS,
        ))
    else:
        findings.append(Finding(
            id="dns_dmarc_present",
            severity=Severity.PASS,
            title="DMARC record present",
            description=f"DMARC policy found for {domain}: {dmarc_found[0][:80]}",
            affected=f"_dmarc.{domain}",
            fix="No action needed.",
            category=Category.DNS,
        ))

    return findings


def _is_ip(value: str) -> bool:
    import re
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value))
