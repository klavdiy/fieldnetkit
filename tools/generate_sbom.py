#!/usr/bin/env python3
"""Generate deterministic CycloneDX and SPDX SBOM files for this repository."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid5, NAMESPACE_URL


REPO_ROOT = Path(__file__).resolve().parent.parent
APP_NAME = "ip_checker"
APP_VERSION = "0.1.0"
SBOM_TIMESTAMP = "2026-01-01T00:00:00Z"


def _components() -> List[Dict[str, Any]]:
    return [
        {
            "type": "framework",
            "name": "python",
            "version": "3.10",
            "purl": "pkg:generic/python@3.10",
            "scope": "required",
        },
        {
            "type": "library",
            "name": "geoip2",
            "purl": "pkg:pypi/geoip2",
            "scope": "optional",
            "description": "Optional enrichment provider (MaxMind)",
        },
        {
            "type": "library",
            "name": "IP2Location",
            "purl": "pkg:pypi/ip2location",
            "scope": "optional",
            "description": "Optional enrichment provider (IP2Location)",
        },
        {
            "type": "application",
            "name": "whois",
            "version": "1.0+",
            "purl": "pkg:generic/whois@1.0",
            "scope": "required",
            "description": "System CLI utility used for ASN/WHOIS lookups",
        },
        {
            "type": "application",
            "name": "ping",
            "purl": "pkg:generic/ping",
            "scope": "required",
            "description": "System CLI utility used in diagnostics",
        },
        {
            "type": "application",
            "name": "traceroute",
            "purl": "pkg:generic/traceroute",
            "scope": "optional",
            "description": "System CLI utility (or tracert on Windows) for route diagnostics",
        },
        {
            "type": "application",
            "name": "tracert",
            "purl": "pkg:generic/tracert",
            "scope": "optional",
            "description": "Windows route diagnostics utility alternative to traceroute",
        },
        {
            "type": "application",
            "name": "nslookup",
            "purl": "pkg:generic/nslookup",
            "scope": "optional",
            "description": "System CLI utility for DNS checks",
        },
        {
            "type": "application",
            "name": "nmap",
            "purl": "pkg:generic/nmap",
            "scope": "optional",
            "description": "System CLI utility for extended network scanning",
        },
        {
            "type": "application",
            "name": "tcpdump",
            "purl": "pkg:generic/tcpdump",
            "scope": "optional",
            "description": "System CLI utility for packet capture and fallback PCAP read",
        },
        {
            "type": "application",
            "name": "tshark",
            "purl": "pkg:generic/tshark",
            "scope": "optional",
            "description": "System CLI utility for detailed PCAP decoding",
        },
    ]


def _cyclonedx(timestamp: str) -> Dict[str, Any]:
    comps = _components()
    component_refs: List[str] = []
    for item in comps:
        item["bom-ref"] = item["purl"]
        component_refs.append(item["bom-ref"])

    stable_payload = {
        "app": f"{APP_NAME}@{APP_VERSION}",
        "components": component_refs,
    }
    serial = f"urn:uuid:{uuid5(NAMESPACE_URL, json.dumps(stable_payload, sort_keys=True))}"

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": serial,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "klavdiy", "name": "generate_sbom.py"}],
            "component": {
                "bom-ref": f"app:{APP_NAME}@{APP_VERSION}",
                "type": "application",
                "name": APP_NAME,
                "version": APP_VERSION,
                "description": "CLI utility for IP/ASN geo checks and network diagnostics",
                "licenses": [{"license": {"id": "MIT"}}],
            },
        },
        "components": comps,
        "dependencies": [{"ref": f"app:{APP_NAME}@{APP_VERSION}", "dependsOn": component_refs}],
    }


def _spdx_package(comp: Dict[str, Any]) -> Dict[str, Any]:
    purl = comp["purl"]
    package_spdx_id = "SPDXRef-" + hashlib.sha1(purl.encode("utf-8")).hexdigest()[:12]
    return {
        "SPDXID": package_spdx_id,
        "name": comp["name"],
        "versionInfo": comp.get("version", "UNKNOWN"),
        "downloadLocation": "NOASSERTION",
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "filesAnalyzed": False,
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ],
        "primaryPackagePurpose": "LIBRARY" if comp["type"] == "library" else "APPLICATION",
        "description": comp.get("description", ""),
    }


def _spdx(timestamp: str) -> Dict[str, Any]:
    comps = _components()
    packages = [_spdx_package(c) for c in comps]
    app_spdx_id = "SPDXRef-Package-ip_checker"

    relationships = []
    for pkg in packages:
        relationships.append(
            {
                "spdxElementId": app_spdx_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": pkg["SPDXID"],
            }
        )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{APP_NAME}-sbom",
        "documentNamespace": f"https://example.local/spdx/{APP_NAME}/{hashlib.sha1(timestamp.encode()).hexdigest()[:12]}",
        "creationInfo": {
            "created": timestamp,
            "creators": ["Tool: generate_sbom.py"],
            "licenseListVersion": "3.25",
        },
        "documentDescribes": [app_spdx_id],
        "packages": [
            {
                "SPDXID": app_spdx_id,
                "name": APP_NAME,
                "versionInfo": APP_VERSION,
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "filesAnalyzed": False,
                "primaryPackagePurpose": "APPLICATION",
            },
            *packages,
        ],
        "relationships": relationships,
    }


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    timestamp = SBOM_TIMESTAMP
    _write_json(REPO_ROOT / "sbom.cdx.json", _cyclonedx(timestamp))
    _write_json(REPO_ROOT / "sbom.spdx.json", _spdx(timestamp))
    print("Generated sbom.cdx.json and sbom.spdx.json")


if __name__ == "__main__":
    main()
