#!/usr/bin/env python3
"""
Local intelligence cache — persist FNkit lookup results under ``data/cache/intel/``.

Kinds: ``geo``, ``whois``, ``bgp``, ``pdns``, ``enrichment_maxmind``, ``enrichment_ip2location``.
Config: ``data/config/.intel_cache.json`` (see ``intel_cache.example.json``).
"""

from __future__ import annotations

import copy
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from paths import CONFIG_DIR, INTEL_CACHE_CONFIG_FILE, INTEL_CACHE_DIR

CACHE_FORMAT = "fnkit.intel_cache/1"

CACHE_KINDS = (
    "geo",
    "whois",
    "bgp",
    "pdns",
    "enrichment_maxmind",
    "enrichment_ip2location",
)

DEFAULT_TTLS: Dict[str, int] = {
    "geo": 24 * 3600,
    "whois": 7 * 24 * 3600,
    "bgp": 6 * 3600,
    "pdns": 12 * 3600,
    "enrichment_maxmind": 24 * 3600,
    "enrichment_ip2location": 24 * 3600,
}

DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": True,
    "show_hits": False,
    "ttl_seconds": dict(DEFAULT_TTLS),
}

_RUNTIME_DISABLED = False
_RUNTIME_FORCE_REFRESH = False
_RUNTIME_VERBOSE_HITS = False

STRINGS: Dict[str, Dict[str, str]] = {
    "en": {
        "hit": "Local intelligence cache: {kind} {key} (age {age})",
        "stats_title": "Local intelligence cache",
        "stats_line": "  {kind}: {n} entries ({size})",
        "stats_total": "Total: {n} entries, {size}",
        "cleared": "Cleared {n} cache file(s).",
        "saved": "Settings saved.",
        "disabled": "Local intelligence cache is disabled.",
    },
    "ru": {
        "hit": "Локальный intelligence cache: {kind} {key} (возраст {age})",
        "stats_title": "Локальный intelligence cache",
        "stats_line": "  {kind}: {n} записей ({size})",
        "stats_total": "Всего: {n} записей, {size}",
        "cleared": "Удалено файлов кэша: {n}.",
        "saved": "Настройки сохранены.",
        "disabled": "Локальный intelligence cache отключён.",
    },
}


def msg(lang: str, key: str, **kwargs: Any) -> str:
    table = STRINGS.get(lang if lang in STRINGS else "en", STRINGS["en"])
    return table.get(key, key).format(**kwargs)


def set_runtime_options(
    *,
    disabled: bool = False,
    force_refresh: bool = False,
    verbose_hits: bool = False,
) -> None:
    global _RUNTIME_DISABLED, _RUNTIME_FORCE_REFRESH, _RUNTIME_VERBOSE_HITS
    _RUNTIME_DISABLED = disabled
    _RUNTIME_FORCE_REFRESH = force_refresh
    _RUNTIME_VERBOSE_HITS = verbose_hits


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_ts(iso: str) -> float:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _human_age(seconds: float, lang: str = "en") -> str:
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m"
    if seconds < 86400:
        h = int(seconds // 3600)
        return f"{h}h" if lang == "en" else f"{h}ч"
    d = int(seconds // 86400)
    return f"{d}d" if lang == "en" else f"{d}д"


def normalize_config(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if not isinstance(raw, dict):
        return cfg
    if "enabled" in raw:
        cfg["enabled"] = bool(raw["enabled"])
    if "show_hits" in raw:
        cfg["show_hits"] = bool(raw["show_hits"])
    ttl_in = raw.get("ttl_seconds")
    if isinstance(ttl_in, dict):
        for kind in CACHE_KINDS:
            if kind in ttl_in:
                try:
                    cfg["ttl_seconds"][kind] = max(60, int(ttl_in[kind]))
                except (TypeError, ValueError):
                    pass
    return cfg


def load_config() -> Dict[str, Any]:
    try:
        if INTEL_CACHE_CONFIG_FILE.exists():
            with open(INTEL_CACHE_CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return normalize_config(data)
    except Exception:
        pass
    return normalize_config(None)


def save_config(config: Dict[str, Any]) -> bool:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(INTEL_CACHE_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(normalize_config(config), f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def is_enabled() -> bool:
    if _RUNTIME_DISABLED:
        return False
    return bool(load_config().get("enabled", True))


def ttl_for_kind(kind: str) -> int:
    cfg = load_config()
    ttls = cfg.get("ttl_seconds") or {}
    return int(ttls.get(kind, DEFAULT_TTLS.get(kind, 3600)))


def _sanitize_key(key: str) -> str:
    safe = re.sub(r"[^\w.\-|]+", "_", (key or "").strip())[:180]
    return safe or "unknown"


def _entry_path(kind: str, key: str) -> Path:
    return INTEL_CACHE_DIR / kind / f"{_sanitize_key(key)}.json"


def _is_cacheable(kind: str, payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("error"):
        return False
    if kind == "geo":
        return bool(payload.get("success"))
    if kind == "bgp":
        return bool(payload.get("success"))
    if kind == "pdns":
        return bool(payload.get("success"))
    if kind.startswith("enrichment_"):
        return bool(payload.get("available"))
    if kind == "whois":
        return bool(payload.get("asn") or payload.get("country") or payload.get("org") or payload.get("whois_text"))
    return True


def get(kind: str, key: str) -> Optional[Dict[str, Any]]:
    """Return cached payload if present and not expired."""
    if not is_enabled() or kind not in CACHE_KINDS:
        return None
    path = _entry_path(kind, key)
    if not path.is_file():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    expires = doc.get("expires_at")
    if expires and _parse_ts(str(expires)) < time.time():
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    payload = doc.get("payload")
    return payload if isinstance(payload, dict) else None


def format_entry_age(kind: str, key: str, *, lang: str = "en") -> str:
    meta = get_entry_meta(kind, key)
    if not meta:
        return "?"
    return _human_age(float(meta.get("age_seconds") or 0), lang)


def get_entry_meta(kind: str, key: str) -> Optional[Dict[str, Any]]:
    path = _entry_path(kind, key)
    if not path.is_file():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception:
        return None
    fetched = doc.get("fetched_at")
    if not fetched:
        return None
    age = time.time() - _parse_ts(str(fetched))
    return {"kind": kind, "key": key, "fetched_at": fetched, "age_seconds": age}


def put(
    kind: str,
    key: str,
    payload: Dict[str, Any],
    *,
    ttl_sec: Optional[int] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> bool:
    if not is_enabled() or kind not in CACHE_KINDS:
        return False
    if not _is_cacheable(kind, payload):
        return False
    ttl = ttl_sec if ttl_sec is not None else ttl_for_kind(kind)
    now = time.time()
    doc = {
        "format": CACHE_FORMAT,
        "kind": kind,
        "key": key,
        "fetched_at": _utc_now(),
        "expires_at": datetime.fromtimestamp(now + ttl, tz=timezone.utc).isoformat(timespec="seconds"),
        "ttl_seconds": ttl,
        "payload": payload,
        "meta": meta or {},
    }
    path = _entry_path(kind, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        tmp = path.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
        tmp.replace(path)
        return True
    except Exception:
        return False


def _should_show_hit() -> bool:
    cfg = load_config()
    return _RUNTIME_VERBOSE_HITS or bool(cfg.get("show_hits"))


def maybe_print_hit(kind: str, key: str, *, lang: str = "en", print_fn: Optional[Callable[[str], None]] = None) -> None:
    if not _should_show_hit():
        return
    meta = get_entry_meta(kind, key)
    if not meta:
        return
    out = print_fn or print
    out(msg(lang, "hit", kind=kind, key=key, age=_human_age(meta["age_seconds"], lang)))


def fetch_or_cache(
    kind: str,
    key: str,
    fetch_fn: Callable[[], Dict[str, Any]],
    *,
    ttl_sec: Optional[int] = None,
    force_refresh: Optional[bool] = None,
    lang: str = "en",
    print_fn: Optional[Callable[[str], None]] = None,
) -> Tuple[Dict[str, Any], bool]:
    """
    Return ``(payload, from_cache)``.
    On miss, calls ``fetch_fn()`` and stores successful responses.
    """
    refresh = _RUNTIME_FORCE_REFRESH if force_refresh is None else force_refresh
    if is_enabled() and not refresh:
        cached = get(kind, key)
        if cached is not None:
            maybe_print_hit(kind, key, lang=lang, print_fn=print_fn)
            return cached, True

    payload = fetch_fn()
    if isinstance(payload, dict):
        put(kind, key, payload, ttl_sec=ttl_sec)
    return payload if isinstance(payload, dict) else {}, False


def clear(kind: Optional[str] = None, key: Optional[str] = None) -> int:
    """Remove cache files; returns count removed."""
    if not INTEL_CACHE_DIR.exists():
        return 0
    removed = 0
    kinds = [kind] if kind and kind in CACHE_KINDS else list(CACHE_KINDS)
    for k in kinds:
        base = INTEL_CACHE_DIR / k
        if not base.is_dir():
            continue
        if key:
            path = _entry_path(k, key)
            if path.is_file():
                path.unlink(missing_ok=True)
                removed += 1
            continue
        for path in base.glob("*.json"):
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
    return removed


def _fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


def stats() -> Dict[str, Any]:
    per_kind: Dict[str, Dict[str, int]] = {}
    total_n = 0
    total_bytes = 0
    for kind in CACHE_KINDS:
        base = INTEL_CACHE_DIR / kind
        n = 0
        size = 0
        if base.is_dir():
            for path in base.glob("*.json"):
                if path.name.endswith(".tmp"):
                    continue
                n += 1
                try:
                    size += path.stat().st_size
                except OSError:
                    pass
        per_kind[kind] = {"entries": n, "bytes": size}
        total_n += n
        total_bytes += size
    return {"per_kind": per_kind, "total_entries": total_n, "total_bytes": total_bytes}


def format_stats(lang: str = "en") -> str:
    s = stats()
    lines = [msg(lang, "stats_title")]
    for kind in CACHE_KINDS:
        block = s["per_kind"].get(kind, {})
        lines.append(
            msg(
                lang,
                "stats_line",
                kind=kind,
                n=block.get("entries", 0),
                size=_fmt_size(block.get("bytes", 0)),
            )
        )
    lines.append(
        msg(
            lang,
            "stats_total",
            n=s["total_entries"],
            size=_fmt_size(s["total_bytes"]),
        )
    )
    cfg = load_config()
    lines.append(f"  enabled={cfg.get('enabled')} show_hits={cfg.get('show_hits')}")
    return "\n".join(lines)


def configure_intel_cache_interactive(
    *,
    lang: str = "en",
    print_fn: Optional[Callable[[str], None]] = None,
    input_fn: Optional[Callable[[str], str]] = None,
) -> None:
    out = print_fn or print
    ask = input_fn or input
    labels = {
        "en": {
            "title": "Local intelligence cache",
            "1": "1. Show stats",
            "2": "2. Clear all entries",
            "3": "3. Toggle enabled",
            "4": "4. Toggle show cache hits in output",
            "0": "0. Back",
            "prompt": "Select (0-4): ",
        },
        "ru": {
            "title": "Локальный intelligence cache",
            "1": "1. Показать статистику",
            "2": "2. Очистить весь кэш",
            "3": "3. Вкл/выкл кэш",
            "4": "4. Показывать cache hit в выводе",
            "0": "0. Назад",
            "prompt": "Выберите (0-4): ",
        },
    }
    L = labels.get(lang if lang in labels else "en", labels["en"])

    while True:
        out("")
        out(L["title"])
        for k in ("1", "2", "3", "4", "0"):
            out(L[k])
        try:
            choice = ask(L["prompt"]).strip()
        except (EOFError, KeyboardInterrupt):
            out("")
            return
        if choice == "0":
            return
        cfg = load_config()
        if choice == "1":
            out(format_stats(lang))
        elif choice == "2":
            n = clear()
            out(msg(lang, "cleared", n=n))
        elif choice == "3":
            cfg["enabled"] = not cfg.get("enabled", True)
            save_config(cfg)
            out(msg(lang, "saved"))
        elif choice == "4":
            cfg["show_hits"] = not cfg.get("show_hits", False)
            save_config(cfg)
            out(msg(lang, "saved"))
        else:
            continue
