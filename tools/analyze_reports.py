#!/usr/bin/env python3
"""
Offline "security analyst" report generator for WebRecon JSON outputs.

This intentionally does NOT call any external AI/LLM by default. It produces a
deterministic, human-readable Markdown analysis based on the scan artifacts.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


COMMON_SUFFIXES = [
    "com",
    "org",
    "net",
    "io",
    "au",
    "group",
]


def _domain_from_filename(stem: str) -> str | None:
    # Expect stems like: "bruteforcegroup_http" or "borrowmanau_https"
    base = stem
    if base.endswith("_http"):
        base = base[: -len("_http")]
    if base.endswith("_https"):
        base = base[: -len("_https")]

    for suffix in sorted(COMMON_SUFFIXES, key=len, reverse=True):
        if base.endswith(suffix) and len(base) > len(suffix):
            return f"{base[: -len(suffix)]}.{suffix}"
    return None


def _netloc_from_url(url: str) -> str | None:
    try:
        return (urlparse(url).hostname or "").lower() or None
    except Exception:
        return None


def _scheme_from_filename(stem: str) -> str | None:
    if stem.endswith("_http"):
        return "http"
    if stem.endswith("_https"):
        return "https"
    return None


def _uniq_sorted(values: list[str]) -> list[str]:
    return sorted({v for v in values if v})


@dataclass(frozen=True)
class ScanReport:
    path: Path
    domain: str
    scheme: str
    data: dict[str, Any]

    @property
    def crawled_links(self) -> list[str]:
        return list(self.data.get("crawled_links") or [])

    @property
    def redirects(self) -> list[dict[str, Any]]:
        return list(self.data.get("redirects") or [])

    @property
    def emails(self) -> list[str]:
        return _uniq_sorted(list(self.data.get("emails") or []))

    @property
    def technologies(self) -> list[str]:
        techs = self.data.get("technologies", {}).get("detected") or []
        return _uniq_sorted(list(techs))


def load_report(path: Path) -> ScanReport:
    data = json.loads(path.read_text(encoding="utf-8"))

    stem = path.stem
    scheme = _scheme_from_filename(stem) or "unknown"

    # Prefer deriving the domain from data
    domain = None
    crawled = data.get("crawled_links") or []
    if crawled:
        domain = _netloc_from_url(crawled[0])
    if not domain:
        redirects = data.get("redirects") or []
        if redirects:
            domain = _netloc_from_url(redirects[0].get("from", "")) or _netloc_from_url(
                redirects[0].get("to", "")
            )
    if not domain:
        domain = _domain_from_filename(stem)

    if not domain:
        domain = f"unknown({path.name})"

    return ScanReport(path=path, domain=domain, scheme=scheme, data=data)


def analyze_domain(domain: str, reports: dict[str, ScanReport]) -> str:
    http = reports.get("http")
    https = reports.get("https")

    lines: list[str] = []
    lines.append(f"## {domain}")

    def _summarize(r: ScanReport) -> list[str]:
        c = len(r.crawled_links)
        emails = r.emails
        techs = r.technologies
        redirects = r.redirects

        out: list[str] = []
        out.append(f"- **{r.scheme.upper()}**: crawled_links={c}, emails={len(emails)}, tech={len(techs)}, redirects={len(redirects)}")
        if redirects:
            # Show first redirect only (park pages often just do http->https)
            first = redirects[0]
            out.append(
                f"  - **redirect**: {first.get('from')} → {first.get('to')} (status={first.get('status_code')}, allowed={first.get('allowed')})"
            )
        if emails:
            out.append(f"  - **emails**: {', '.join(emails)}")
        if techs:
            out.append(f"  - **tech**: {', '.join(techs)}")
        return out

    if http:
        lines.extend(_summarize(http))
    else:
        lines.append("- **HTTP**: (no report)")

    if https:
        lines.extend(_summarize(https))
    else:
        lines.append("- **HTTPS**: (no report)")

    # Assessment (rule-based)
    lines.append("")
    lines.append("### Assessment")

    # Redirect posture
    if http and http.redirects:
        # If first redirect goes to https, good baseline hygiene.
        first = http.redirects[0]
        to = first.get("to", "") or ""
        if to.startswith("https://"):
            lines.append("- **HTTP→HTTPS redirect present**: good baseline (reduces accidental plaintext traffic).")
        else:
            lines.append("- **Redirects observed**, but not clearly HTTP→HTTPS. Review redirect target.")
    elif http:
        lines.append("- **No redirects recorded on HTTP**: verify whether HTTP is disabled, served, or blocked.")

    # Email exposure
    all_emails: list[str] = []
    if http:
        all_emails.extend(http.emails)
    if https:
        all_emails.extend(https.emails)
    all_emails = _uniq_sorted(all_emails)
    if all_emails:
        lines.append("- **Email(s) exposed in page content**: increases spam/phishing risk.")
        lines.append("  - **Recommendation**: use an alias, obfuscation, or a contact form on parked pages.")
    else:
        lines.append("- **No emails extracted** from scanned content.")

    # Tech notes
    all_tech: list[str] = []
    if http:
        all_tech.extend(http.technologies)
    if https:
        all_tech.extend(https.technologies)
    all_tech = _uniq_sorted(all_tech)
    if all_tech:
        if "Cloudflare" in all_tech:
            lines.append("- **Cloudflare detected**: likely CDN/WAF in front of origin; enable HSTS + appropriate WAF/bot rules.")
        if "Hotjar" in all_tech:
            lines.append("- **Hotjar detected**: confirm intentional (privacy/compliance) and avoid deploying on parked/placeholder pages.")

    # Crawlability / blocking
    if https and len(https.crawled_links) == 0:
        lines.append("- **HTTPS crawl did not retrieve body content** (crawled_links empty).")
        lines.append("  - **Possible causes**: WAF/bot-blocking, 403/401, challenge pages, or network policy.")
        lines.append("  - **Recommendation**: if you expect public access, confirm behavior for normal browsers and for monitoring/user-agents you care about.")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a Markdown security analysis from WebRecon JSON reports.")
    parser.add_argument("reports", nargs="+", help="Paths to WebRecon JSON report files.")
    args = parser.parse_args()

    report_paths = [Path(p).expanduser().resolve() for p in args.reports]
    scans = [load_report(p) for p in report_paths]

    by_domain: dict[str, dict[str, ScanReport]] = {}
    for scan in scans:
        by_domain.setdefault(scan.domain, {})[scan.scheme] = scan

    md: list[str] = []
    md.append("# WebRecon Analysis (Offline)")
    md.append("")
    md.append("This analysis is generated from WebRecon JSON outputs and does **not** call external AI/LLMs.")
    md.append("")

    for domain in sorted(by_domain.keys()):
        md.append(analyze_domain(domain, by_domain[domain]))
        md.append("")

    print("\n".join(md).rstrip() + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


