#!/usr/bin/env python3
"""Generate a CSAF 2.0 VEX document from GitHub Dependabot alerts.

This script queries the GitHub Dependabot alerts API for the current
repository and produces a CSAF VEX (Vulnerability Exploitability eXchange)
document that describes the known vulnerability status of the project.

Required environment variables:
    GH_TOKEN   – A GitHub token with permission to read Dependabot alerts.
                 A PAT with the `security_events` scope (classic) or
                 `vulnerability_alerts:read` (fine-grained) is typically
                 required because the default GITHUB_TOKEN does not have
                 access to the Dependabot alerts API.
    GITHUB_REPOSITORY – Owner/repo (set automatically by GitHub Actions).
    GITHUB_SERVER_URL – GitHub server URL (set automatically by GitHub Actions).
    GITHUB_SHA        – Current commit SHA (set automatically by GitHub Actions).
"""

import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GH_TOKEN = os.environ.get("GH_TOKEN", "")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "")
GITHUB_SERVER_URL = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
GITHUB_SHA = os.environ.get("GITHUB_SHA", "unknown")
API_BASE = os.environ.get("GITHUB_API_URL", "https://api.github.com")
OUTPUT_FILE = os.environ.get("VEX_OUTPUT_FILE", "csaf-vex.json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def gh_api_get(path: str) -> list | dict:
    """Perform an authenticated GET against the GitHub REST API.

    Paginates automatically and returns the aggregated JSON list when the
    endpoint returns an array, or a single dict otherwise.
    """
    url = f"{API_BASE}{path}"
    results: list = []

    while url:
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        if GH_TOKEN:
            req.add_header("Authorization", f"Bearer {GH_TOKEN}")

        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())

        # If the response is not a list we just return the object directly.
        if not isinstance(data, list):
            return data

        results.extend(data)

        # Follow pagination via the Link header.
        link_header = resp.headers.get("Link", "")
        url = _parse_next_link(link_header)

    return results


def _parse_next_link(link_header: str) -> str | None:
    """Extract the URL for rel=\"next\" from a Link header."""
    for part in link_header.split(","):
        if 'rel="next"' in part:
            url = part.split(";")[0].strip().strip("<>")
            return url
    return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Dependabot alert → CSAF VEX mapping
# ---------------------------------------------------------------------------

# Dependabot states → CSAF product_status categories
_STATE_MAP: dict[str, str] = {
    "open": "known_affected",
    "fixed": "fixed",
    "dismissed": "known_not_affected",
    "auto_dismissed": "known_not_affected",
}


def _build_product_id(alert: dict) -> str:
    """Build a unique CSAF product ID for the affected dependency."""
    dep = alert.get("dependency", {})
    pkg = dep.get("package", {})
    name = pkg.get("name", "unknown")
    ecosystem = pkg.get("ecosystem", "unknown")
    manifest = dep.get("manifest_path", "")
    return f"{ecosystem}:{name}:{manifest}".rstrip(":")


def _build_vulnerability(alert: dict, product_ids_by_status: dict) -> dict:
    """Map a single Dependabot alert to a CSAF vulnerability object."""
    advisory = alert.get("security_advisory", {})
    vuln: dict = {}

    # CVE
    cve_id = alert.get("security_advisory", {}).get("cve_id")
    if cve_id:
        vuln["cve"] = cve_id

    # Title / notes
    title = advisory.get("summary", "")
    vuln["title"] = title
    vuln["notes"] = [
        {
            "category": "description",
            "text": advisory.get("description", title),
        }
    ]

    # Product status
    state = alert.get("state", "open")
    status_category = _STATE_MAP.get(state, "under_investigation")
    product_id = _build_product_id(alert)
    product_ids_by_status.setdefault(status_category, set()).add(product_id)
    vuln["product_status"] = {status_category: [product_id]}

    # Threats / justifications for dismissed alerts
    if state in ("dismissed", "auto_dismissed"):
        reason = alert.get("dismissed_reason", "")
        comment = alert.get("dismissed_comment", "")
        detail = reason
        if comment:
            detail = f"{reason}: {comment}" if reason else comment
        vuln["threats"] = [
            {
                "category": "impact",
                "details": detail or "Dismissed without further detail.",
                "product_ids": [product_id],
            }
        ]

    # Remediations for fixed alerts
    if state == "fixed":
        fixed_at = alert.get("fixed_at", "")
        vuln["remediations"] = [
            {
                "category": "vendor_fix",
                "details": f"Fixed at {fixed_at}." if fixed_at else "Fixed.",
                "product_ids": [product_id],
            }
        ]

    # Remediations for open alerts (upgrade recommendation)
    if state == "open":
        first_patched = ""
        vulns = advisory.get("vulnerabilities", [])
        if vulns:
            first_patched = vulns[0].get("first_patched_version", {})
            if isinstance(first_patched, dict):
                first_patched = first_patched.get("identifier", "")
        if first_patched:
            vuln["remediations"] = [
                {
                    "category": "vendor_fix",
                    "details": f"Upgrade to version {first_patched} or later.",
                    "product_ids": [product_id],
                }
            ]

    # References
    refs = []
    html_url = alert.get("html_url", "")
    if html_url:
        refs.append({"category": "external", "summary": "GitHub Dependabot alert", "url": html_url})
    for ref in advisory.get("references", []):
        url = ref if isinstance(ref, str) else ref.get("url", "")
        if url:
            refs.append({"category": "external", "summary": "Advisory reference", "url": url})
    if refs:
        vuln["references"] = refs

    return vuln


# ---------------------------------------------------------------------------
# Build the full CSAF VEX document
# ---------------------------------------------------------------------------


def build_csaf_vex(alerts: list) -> dict:
    """Assemble a CSAF 2.0 VEX document from Dependabot alerts."""
    now = _now_iso()
    repo_url = f"{GITHUB_SERVER_URL}/{GITHUB_REPOSITORY}"

    # -- document metadata ---------------------------------------------------
    document: dict = {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": f"CSAF VEX for {GITHUB_REPOSITORY}",
            "publisher": {
                "category": "vendor",
                "name": GITHUB_REPOSITORY.split("/")[0] if GITHUB_REPOSITORY else "unknown",
                "namespace": repo_url,
            },
            "tracking": {
                "current_release_date": now,
                "id": f"csaf-vex-{GITHUB_REPOSITORY.replace('/', '-')}-{GITHUB_SHA[:8]}",
                "initial_release_date": now,
                "revision_history": [
                    {
                        "date": now,
                        "number": "1",
                        "summary": "Initial automated VEX generation from Dependabot alerts.",
                    }
                ],
                "status": "final",
                "version": "1",
            },
            "notes": [
                {
                    "category": "summary",
                    "text": (
                        "This CSAF VEX document was automatically generated from "
                        "GitHub Dependabot alerts for the repository "
                        f"{GITHUB_REPOSITORY} at commit {GITHUB_SHA}."
                    ),
                }
            ],
            "references": [
                {
                    "category": "self",
                    "summary": "CSAF VEX document",
                    "url": f"{repo_url}/actions",
                }
            ],
        }
    }

    # -- product tree --------------------------------------------------------
    # Collect unique products from all alerts.
    product_branches: list[dict] = []
    seen_products: set[str] = set()
    for alert in alerts:
        pid = _build_product_id(alert)
        if pid in seen_products:
            continue
        seen_products.add(pid)
        dep = alert.get("dependency", {})
        pkg = dep.get("package", {})
        product_branches.append(
            {
                "category": "product_version",
                "name": f"{pkg.get('name', 'unknown')}",
                "product": {
                    "name": f"{pkg.get('name', 'unknown')} ({pkg.get('ecosystem', '')})",
                    "product_id": pid,
                },
            }
        )

    document["product_tree"] = {
        "branches": [
            {
                "category": "vendor",
                "name": GITHUB_REPOSITORY.split("/")[0] if GITHUB_REPOSITORY else "unknown",
                "branches": [
                    {
                        "category": "product_name",
                        "name": GITHUB_REPOSITORY.split("/")[-1] if GITHUB_REPOSITORY else "unknown",
                        "branches": product_branches,
                    }
                ],
            }
        ]
    }

    # -- vulnerabilities -----------------------------------------------------
    product_ids_by_status: dict = {}
    vulnerabilities: list[dict] = []
    for alert in alerts:
        vuln = _build_vulnerability(alert, product_ids_by_status)
        vulnerabilities.append(vuln)

    document["vulnerabilities"] = vulnerabilities

    return document


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    if not GITHUB_REPOSITORY:
        print("::error::GITHUB_REPOSITORY is not set.", file=sys.stderr)
        sys.exit(1)

    if not GH_TOKEN:
        print(
            "::warning::GH_TOKEN is not set. The Dependabot alerts API "
            "typically requires a PAT with the `security_events` scope "
            "(classic) or `vulnerability_alerts:read` (fine-grained). "
            "Falling back to unauthenticated request which will likely fail.",
            file=sys.stderr,
        )

    # Fetch Dependabot alerts ------------------------------------------------
    # Fetch all alerts (open, fixed, dismissed) in a single paginated call
    # to give a complete VEX picture.
    endpoint = f"/repos/{GITHUB_REPOSITORY}/dependabot/alerts?per_page=100"
    print(f"Fetching Dependabot alerts from {API_BASE}{endpoint} …")

    try:
        alerts = gh_api_get(endpoint)
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            print(
                "::error::403 Forbidden – the token does not have permission "
                "to read Dependabot alerts. Please supply a PAT with the "
                "`security_events` scope (classic) or "
                "`vulnerability_alerts:read` permission (fine-grained) as "
                "the DEPENDABOT_ALERTS_TOKEN secret.",
                file=sys.stderr,
            )
            sys.exit(1)
        raise

    if not isinstance(alerts, list):
        print(f"::error::Unexpected API response: {json.dumps(alerts)[:500]}", file=sys.stderr)
        sys.exit(1)

    open_count = sum(1 for a in alerts if a.get("state") == "open")
    fixed_count = sum(1 for a in alerts if a.get("state") == "fixed")
    dismissed_count = sum(1 for a in alerts if a.get("state") in ("dismissed", "auto_dismissed"))
    print(
        f"Fetched {len(alerts)} Dependabot alert(s): "
        f"{open_count} open, {fixed_count} fixed, {dismissed_count} dismissed."
    )

    # Build CSAF VEX document ------------------------------------------------
    vex = build_csaf_vex(alerts)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(vex, fh, indent=2, ensure_ascii=False)

    print(f"CSAF VEX document written to {OUTPUT_FILE} ({len(alerts)} alert(s) total).")


if __name__ == "__main__":
    main()
