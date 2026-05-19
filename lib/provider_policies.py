#!/usr/bin/env python3
"""
Provider priority policies for FNkit (passive DNS, geo enrichment, country conflict).

Stored in ``data/config/.provider_policies.json`` (local, not committed).
Shipped defaults: ``data/config/provider_policies.example.json``.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from paths import CONFIG_DIR, PROVIDER_POLICIES_FILE

PASSIVE_DNS_IDS = ("ripe", "virustotal", "securitytrails")
GEO_IDS = ("ip_api", "maxmind", "ip2location", "whois")

DEFAULT_POLICIES: Dict[str, Any] = {
    "passive_dns": {
        "order": ["ripe", "virustotal", "securitytrails"],
        "enabled": {"ripe": True, "virustotal": True, "securitytrails": True},
        "merge_prefer": "virustotal",
    },
    "geo": {
        "primary": "ip_api",
        "order": ["ip_api", "maxmind", "ip2location"],
        "conflict_prefer": "maxmind",
    },
    "country_conflict": {
        "ipv4": {
            "preferred_source": "GEO_API",
            "weight_geo": 0.6,
            "weight_whois": 0.4,
        },
        "ipv6": {
            "preferred_source": "WHOIS",
            "weight_geo": 0.35,
            "weight_whois": 0.65,
        },
    },
}

STRINGS: Dict[str, Dict[str, str]] = {
    "en": {
        "menu_title": "Provider priority policies",
        "menu_1": "1. Passive DNS — enable/disable providers",
        "menu_2": "2. Passive DNS — query order (comma-separated)",
        "menu_3": "3. Passive DNS — merge preference (hostname attribution)",
        "menu_4": "4. Geo — prefer source on conflict",
        "menu_5": "5. Country conflict — IPv4 weights (geo,whois)",
        "menu_6": "6. Country conflict — IPv6 weights (geo,whois)",
        "menu_7": "7. Reset to defaults",
        "menu_0": "0. Back",
        "prompt": "Select (0-7): ",
        "saved": "Policies saved.",
        "save_failed": "Failed to save policies.",
        "invalid": "Invalid value.",
        "current": "Current:",
        "reset_ok": "Defaults restored.",
        "toggle": "Toggle {id} (currently {state})? (y/n): ",
        "order_hint": "IDs: ripe, virustotal, securitytrails",
        "merge_hint": "One of: ripe, virustotal, securitytrails",
        "geo_hint": "One of: ip_api, maxmind, ip2location, whois",
        "weights_hint": "Two numbers 0–1 separated by comma, e.g. 0.6,0.4",
    },
    "ru": {
        "menu_title": "Политики приоритета провайдеров",
        "menu_1": "1. Passive DNS — вкл/выкл провайдеров",
        "menu_2": "2. Passive DNS — порядок запросов (через запятую)",
        "menu_3": "3. Passive DNS — приоритет при merge hostname",
        "menu_4": "4. Geo — источник при расхождении",
        "menu_5": "5. Country conflict — веса IPv4 (geo,whois)",
        "menu_6": "6. Country conflict — веса IPv6 (geo,whois)",
        "menu_7": "7. Сброс на значения по умолчанию",
        "menu_0": "0. Назад",
        "prompt": "Выберите (0-7): ",
        "saved": "Политики сохранены.",
        "save_failed": "Не удалось сохранить политики.",
        "invalid": "Неверное значение.",
        "current": "Сейчас:",
        "reset_ok": "Восстановлены значения по умолчанию.",
        "toggle": "Переключить {id} (сейчас {state})? (y/n): ",
        "order_hint": "ID: ripe, virustotal, securitytrails",
        "merge_hint": "Один из: ripe, virustotal, securitytrails",
        "geo_hint": "Один из: ip_api, maxmind, ip2location, whois",
        "weights_hint": "Два числа 0–1 через запятую, напр. 0.6,0.4",
    },
}


def msg(lang: str, key: str, **kwargs: Any) -> str:
    table = STRINGS.get(lang if lang in STRINGS else "en", STRINGS["en"])
    return table.get(key, key).format(**kwargs)


def _clamp_weight(value: Any, default: float) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, v))


def _normalize_order(order: Any, allowed: Sequence[str], default: Sequence[str]) -> List[str]:
    if not isinstance(order, list):
        return list(default)
    seen: List[str] = []
    for raw in order:
        pid = str(raw).strip().lower()
        if pid in allowed and pid not in seen:
            seen.append(pid)
    for pid in allowed:
        if pid not in seen:
            seen.append(pid)
    return seen


def normalize_policies(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge user config with defaults and validate."""
    base = copy.deepcopy(DEFAULT_POLICIES)
    if not isinstance(raw, dict):
        return base

    pdns_in = raw.get("passive_dns") if isinstance(raw.get("passive_dns"), dict) else {}
    pdns = base["passive_dns"]
    pdns["order"] = _normalize_order(pdns_in.get("order"), PASSIVE_DNS_IDS, DEFAULT_POLICIES["passive_dns"]["order"])
    enabled_in = pdns_in.get("enabled") if isinstance(pdns_in.get("enabled"), dict) else {}
    enabled = dict(pdns["enabled"])
    for pid in PASSIVE_DNS_IDS:
        if pid in enabled_in:
            enabled[pid] = bool(enabled_in[pid])
    pdns["enabled"] = enabled
    merge_pref = str(pdns_in.get("merge_prefer", pdns["merge_prefer"])).strip().lower()
    pdns["merge_prefer"] = merge_pref if merge_pref in PASSIVE_DNS_IDS else pdns["merge_prefer"]

    geo_in = raw.get("geo") if isinstance(raw.get("geo"), dict) else {}
    geo = base["geo"]
    geo["order"] = _normalize_order(geo_in.get("order"), GEO_IDS[:3], DEFAULT_POLICIES["geo"]["order"])
    primary = str(geo_in.get("primary", geo["primary"])).strip().lower()
    geo["primary"] = primary if primary in GEO_IDS else geo["primary"]
    conflict = str(geo_in.get("conflict_prefer", geo["conflict_prefer"])).strip().lower()
    geo["conflict_prefer"] = conflict if conflict in GEO_IDS else geo["conflict_prefer"]

    cc_in = raw.get("country_conflict") if isinstance(raw.get("country_conflict"), dict) else {}
    cc = base["country_conflict"]
    for family in ("ipv4", "ipv6"):
        block_in = cc_in.get(family) if isinstance(cc_in.get(family), dict) else {}
        block = dict(cc[family])
        block["weight_geo"] = _clamp_weight(block_in.get("weight_geo"), block["weight_geo"])
        block["weight_whois"] = _clamp_weight(block_in.get("weight_whois"), block["weight_whois"])
        pref = str(block_in.get("preferred_source", block["preferred_source"])).upper()
        if pref in ("GEO_API", "WHOIS"):
            block["preferred_source"] = pref
        cc[family] = block

    return base


def load_policies() -> Dict[str, Any]:
    try:
        if PROVIDER_POLICIES_FILE.exists():
            with open(PROVIDER_POLICIES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return normalize_policies(data)
    except Exception:
        pass
    return normalize_policies(None)


def save_policies(policies: Dict[str, Any]) -> bool:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    normalized = normalize_policies(policies)
    try:
        with open(PROVIDER_POLICIES_FILE, "w", encoding="utf-8") as f:
            json.dump(normalized, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def passive_dns_enabled(provider: str, policies: Optional[Dict[str, Any]] = None) -> bool:
    pol = policies or load_policies()
    enabled = (pol.get("passive_dns") or {}).get("enabled") or {}
    return bool(enabled.get(provider, True))


def passive_dns_order(policies: Optional[Dict[str, Any]] = None) -> List[str]:
    pol = policies or load_policies()
    order = (pol.get("passive_dns") or {}).get("order") or list(PASSIVE_DNS_IDS)
    return [p for p in order if passive_dns_enabled(p, pol)]


def passive_dns_merge_rank(source: Optional[str], policies: Optional[Dict[str, Any]] = None) -> int:
    """Lower rank = higher priority for sorting merged hostnames."""
    pol = policies or load_policies()
    order = passive_dns_order(pol)
    merge_pref = str((pol.get("passive_dns") or {}).get("merge_prefer") or "virustotal").lower()
    rank_map = {pid: idx for idx, pid in enumerate(order)}
    if merge_pref in rank_map:
        rank_map[merge_pref] = -1
    parts = [p.strip() for p in str(source or "").split("+") if p.strip()]
    if not parts:
        return 999
    return min(rank_map.get(p, 99) for p in parts)


def country_conflict_weights_for_ip(ip: str, policies: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return weight block for IPv4 or IPv6 from policies (used by fnkit conflict resolver)."""
    pol = policies or load_policies()
    try:
        import ipaddress

        family = "ipv6" if ipaddress.ip_address(ip).version == 6 else "ipv4"
    except ValueError:
        family = "ipv4"
    block = (pol.get("country_conflict") or {}).get(family) or DEFAULT_POLICIES["country_conflict"][family]
    return dict(block)


def geo_conflict_prefer(policies: Optional[Dict[str, Any]] = None) -> str:
    pol = policies or load_policies()
    return str((pol.get("geo") or {}).get("conflict_prefer") or "maxmind").lower()


def pick_geo_country(
    *,
    ip_api: Optional[str],
    maxmind: Optional[str],
    ip2location: Optional[str],
    policies: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Pick country code when enrichment sources disagree (policy-driven)."""
    pol = policies or load_policies()
    prefer = geo_conflict_prefer(pol)
    values = {
        "ip_api": (ip_api or "").upper() or None,
        "maxmind": (maxmind or "").upper() or None,
        "ip2location": (ip2location or "").upper() or None,
    }
    if prefer in values and values[prefer]:
        return values[prefer]
    for pid in (pol.get("geo") or {}).get("order") or GEO_IDS:
        cc = values.get(pid)
        if cc:
            return cc
    return values.get("ip_api") or values.get("maxmind") or values.get("ip2location")


def format_policies_summary(policies: Optional[Dict[str, Any]] = None) -> str:
    pol = policies or load_policies()
    pdns = pol.get("passive_dns") or {}
    geo = pol.get("geo") or {}
    cc4 = (pol.get("country_conflict") or {}).get("ipv4") or {}
    cc6 = (pol.get("country_conflict") or {}).get("ipv6") or {}
    en = pdns.get("enabled") or {}
    lines = [
        f"passive_dns order={pdns.get('order')} enabled={en} merge_prefer={pdns.get('merge_prefer')}",
        f"geo primary={geo.get('primary')} conflict_prefer={geo.get('conflict_prefer')}",
        f"country_conflict ipv4 geo={cc4.get('weight_geo')} whois={cc4.get('weight_whois')}",
        f"country_conflict ipv6 geo={cc6.get('weight_geo')} whois={cc6.get('weight_whois')}",
    ]
    return "\n".join(lines)


def configure_policies_interactive(
    *,
    lang: str = "en",
    print_fn: Optional[Callable[[str], None]] = None,
    input_fn: Optional[Callable[[str], str]] = None,
) -> None:
    out = print_fn or print
    ask = input_fn or input
    policies = load_policies()

    while True:
        out("")
        out(msg(lang, "menu_title"))
        for key in ("menu_1", "menu_2", "menu_3", "menu_4", "menu_5", "menu_6", "menu_7", "menu_0"):
            out(msg(lang, key))
        out(f"{msg(lang, 'current')}\n{format_policies_summary(policies)}")
        try:
            choice = ask(msg(lang, "prompt")).strip()
        except (EOFError, KeyboardInterrupt):
            out("")
            return

        if choice == "0":
            return
        if choice == "7":
            policies = normalize_policies(None)
            if save_policies(policies):
                out(msg(lang, "reset_ok"))
            else:
                out(msg(lang, "save_failed"))
            continue

        pdns = policies.setdefault("passive_dns", copy.deepcopy(DEFAULT_POLICIES["passive_dns"]))
        geo = policies.setdefault("geo", copy.deepcopy(DEFAULT_POLICIES["geo"]))
        cc = policies.setdefault("country_conflict", copy.deepcopy(DEFAULT_POLICIES["country_conflict"]))

        if choice == "1":
            enabled = dict(pdns.get("enabled") or {})
            for pid in PASSIVE_DNS_IDS:
                state = "on" if enabled.get(pid, True) else "off"
                try:
                    ans = ask(msg(lang, "toggle", id=pid, state=state)).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    return
                if ans == "y":
                    enabled[pid] = not enabled.get(pid, True)
            pdns["enabled"] = enabled
        elif choice == "2":
            out(msg(lang, "order_hint"))
            try:
                raw = ask("> ").strip()
            except (EOFError, KeyboardInterrupt):
                return
            order = [p.strip().lower() for p in raw.split(",") if p.strip()]
            if not order:
                out(msg(lang, "invalid"))
                continue
            pdns["order"] = order
        elif choice == "3":
            out(msg(lang, "merge_hint"))
            try:
                raw = ask("> ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return
            if raw not in PASSIVE_DNS_IDS:
                out(msg(lang, "invalid"))
                continue
            pdns["merge_prefer"] = raw
        elif choice == "4":
            out(msg(lang, "geo_hint"))
            try:
                raw = ask("> ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return
            if raw not in GEO_IDS:
                out(msg(lang, "invalid"))
                continue
            geo["conflict_prefer"] = raw
        elif choice in ("5", "6"):
            family = "ipv4" if choice == "5" else "ipv6"
            out(msg(lang, "weights_hint"))
            try:
                raw = ask("> ").strip()
            except (EOFError, KeyboardInterrupt):
                return
            parts = [p.strip() for p in raw.split(",")]
            if len(parts) != 2:
                out(msg(lang, "invalid"))
                continue
            block = dict(cc.get(family) or DEFAULT_POLICIES["country_conflict"][family])
            block["weight_geo"] = _clamp_weight(parts[0], block["weight_geo"])
            block["weight_whois"] = _clamp_weight(parts[1], block["weight_whois"])
            block["preferred_source"] = "WHOIS" if block["weight_whois"] > block["weight_geo"] else "GEO_API"
            cc[family] = block
        else:
            continue

        policies = normalize_policies(policies)
        if save_policies(policies):
            out(msg(lang, "saved"))
        else:
            out(msg(lang, "save_failed"))
