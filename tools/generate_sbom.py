#!/usr/bin/env python3
"""Generate CycloneDX and SPDX SBOM files from dependencies.manifest.json."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List
from uuid import NAMESPACE_URL, uuid5


REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "dependencies.manifest.json"
APP_NAME = "fieldnetkit"
# Fixed timestamp keeps SBOM diffs stable unless manifest or version change.
SBOM_TIMESTAMP = "2026-05-19T12:00:00Z"


def _load_manifest() -> Dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _cyclonedx_type(dep_type: str) -> str:
    mapping = {
        "framework": "framework",
        "library": "library",
        "application": "application",
        "service": "service",
    }
    return mapping.get(dep_type, "library")


def _component_from_dep(dep: Dict[str, Any]) -> Dict[str, Any]:
    comp: Dict[str, Any] = {
        "type": _cyclonedx_type(dep.get("type", "library")),
        "name": dep.get("name", dep["id"]),
        "purl": dep["purl"],
        "scope": dep.get("scope", "optional"),
        "description": "; ".join(
            filter(
                None,
                [
                    dep.get("description"),
                    f"Modules: {', '.join(dep.get('modules', []))}" if dep.get("modules") else None,
                    f"Feature: {dep.get('feature_group')}" if dep.get("feature_group") else None,
                ],
            )
        )
        or f"Dependency {dep['id']}",
    }
    if dep.get("version"):
        comp["version"] = dep["version"].lstrip(">=")
    lic = dep.get("license")
    if lic and lic != "NOASSERTION":
        comp["licenses"] = [{"license": {"id": lic}}]
    props: List[Dict[str, str]] = []
    if dep.get("feature_group"):
        props.append({"name": "fnkit:featureGroup", "value": dep["feature_group"]})
    install = dep.get("install") or {}
    for platform, block in install.items():
        if isinstance(block, dict):
            for method, value in block.items():
                if method == "note":
                    props.append({"name": f"fnkit:install:{platform}", "value": str(value)})
                elif isinstance(value, list):
                    props.append(
                        {
                            "name": f"fnkit:install:{platform}:{method}",
                            "value": " ".join(str(v) for v in value),
                        }
                    )
                else:
                    props.append({"name": f"fnkit:install:{platform}:{method}", "value": str(value)})
    if props:
        comp["properties"] = props
    return comp


def _components(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [_component_from_dep(d) for d in manifest["dependencies"]]


def _cyclonedx(manifest: Dict[str, Any], timestamp: str) -> Dict[str, Any]:
    app = manifest.get("app", {})
    app_version = app.get("version", "0.1.0")
    comps = _components(manifest)
    component_refs: List[str] = []
    for item in comps:
        item["bom-ref"] = item["purl"]
        component_refs.append(item["purl"])

    stable_payload = {"app": f"{APP_NAME}@{app_version}", "components": sorted(component_refs)}
    serial = f"urn:uuid:{uuid5(NAMESPACE_URL, json.dumps(stable_payload, sort_keys=True))}"

    app_license = app.get("license", "MIT")
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": serial,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {"vendor": "klavdiy", "name": "generate_sbom.py", "version": "2.0.0"},
                {"name": "dependencies.manifest.json", "version": manifest.get("schema", "1")},
            ],
            "component": {
                "bom-ref": f"app:{APP_NAME}@{app_version}",
                "type": "application",
                "name": APP_NAME,
                "version": app_version,
                "description": (
                    "FieldNet Kit (FNkit): IP/ASN geo integrity, network diagnostics, PCAP, DNS graph, OWASP bridge. "
                    "SBOM generated from dependencies.manifest.json"
                ),
                "licenses": [{"license": {"id": app_license}}],
            },
        },
        "components": comps,
        "dependencies": [{"ref": f"app:{APP_NAME}@{app_version}", "dependsOn": component_refs}],
    }


def _spdx_package(comp: Dict[str, Any]) -> Dict[str, Any]:
    purl = comp["purl"]
    package_spdx_id = "SPDXRef-" + hashlib.sha1(purl.encode("utf-8")).hexdigest()[:12]
    purpose = "LIBRARY"
    if comp["type"] == "application":
        purpose = "APPLICATION"
    elif comp["type"] == "service":
        purpose = "OTHER"
    elif comp["type"] == "framework":
        purpose = "FRAMEWORK"
    lic = "NOASSERTION"
    if comp.get("licenses"):
        lic = comp["licenses"][0]["license"].get("id", "NOASSERTION")
    return {
        "SPDXID": package_spdx_id,
        "name": comp["name"],
        "versionInfo": comp.get("version", "UNKNOWN"),
        "downloadLocation": "NOASSERTION",
        "licenseConcluded": lic,
        "licenseDeclared": lic,
        "filesAnalyzed": False,
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ],
        "primaryPackagePurpose": purpose,
        "description": comp.get("description", ""),
    }


def _spdx(manifest: Dict[str, Any], timestamp: str) -> Dict[str, Any]:
    app = manifest.get("app", {})
    app_version = app.get("version", "0.1.0")
    app_license = app.get("license", "MIT")
    comps = _components(manifest)
    packages = [_spdx_package(c) for c in comps]
    app_spdx_id = "SPDXRef-Package-fieldnetkit"

    relationships = [
        {
            "spdxElementId": app_spdx_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": pkg["SPDXID"],
        }
        for pkg in packages
    ]

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{APP_NAME}-sbom",
        "documentNamespace": f"https://example.local/spdx/{APP_NAME}/{hashlib.sha1(timestamp.encode()).hexdigest()[:12]}",
        "creationInfo": {
            "created": timestamp,
            "creators": ["Tool: generate_sbom.py-2.0.0"],
            "licenseListVersion": "3.25",
        },
        "documentDescribes": [app_spdx_id],
        "packages": [
            {
                "SPDXID": app_spdx_id,
                "name": APP_NAME,
                "versionInfo": app_version,
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": app_license,
                "licenseDeclared": app_license,
                "filesAnalyzed": False,
                "primaryPackagePurpose": "APPLICATION",
                "description": "SBOM from dependencies.manifest.json",
            },
            *packages,
        ],
        "relationships": relationships,
    }


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    if not MANIFEST_PATH.is_file():
        raise SystemExit(f"Missing manifest: {MANIFEST_PATH}")
    manifest = _load_manifest()
    _write_json(REPO_ROOT / "sbom.cdx.json", _cyclonedx(manifest, SBOM_TIMESTAMP))
    _write_json(REPO_ROOT / "sbom.spdx.json", _spdx(manifest, SBOM_TIMESTAMP))
    n = len(manifest.get("dependencies", []))
    print(f"Generated sbom.cdx.json and sbom.spdx.json ({n} components from {MANIFEST_PATH.name})")


if __name__ == "__main__":
    main()
