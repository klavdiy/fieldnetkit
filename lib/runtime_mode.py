#!/usr/bin/env python3
"""
Runtime connection profile: online vs offline, optional Tor at startup.

Persisted in ``data/config/.runtime_mode.json`` (local, not committed).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from paths import CONFIG_DIR, RUNTIME_MODE_FILE, TOR_BRIDGES_FILE

_OFFLINE = False

STRINGS: Dict[str, Dict[str, str]] = {
    "en": {
        "mode_title": "Connection mode",
        "mode_online": "1. Online — live API lookups (ip-api, RIPE, WHOIS, passive DNS)",
        "mode_offline": "2. Offline — local ASN DB + intelligence cache only (no live queries)",
        "mode_hint_online": "  Online needs network; uses APIs and can route via Tor.",
        "mode_hint_offline": "  Offline: check pools against cache/DB; menu 12 Tor skipped at setup.",
        "mode_prompt": "Select (1-2): ",
        "tor_title": "Anonymous egress (Tor)",
        "tor_ask": "Route FNkit HTTP(S) API calls through Tor? (y/n): ",
        "tor_skip": "Direct connection — you can enable Tor later in menu 12.",
        "tor_bridges_ask": "Use obfs4 bridges? (needed if Tor is blocked) (y/n): ",
        "tor_bridges_yes": "  Add Bridge lines to: {path}",
        "tor_bridges_link": "  https://bridges.torproject.org/",
        "tor_country_ask": "Exit country (optional). Examples: de | de,us | {de},{us} | empty=any: ",
        "tor_country_hint": "  ISO 3166-1 alpha-2 codes; comma-separated or Tor brace form.",
        "tor_starting": "Starting Tor…",
        "tor_ok": "Tor active. API traffic uses SOCKS.",
        "tor_warn": "Tor setup incomplete: {msg}",
        "tor_fail": "Could not enable Tor: {msg}",
        "invalid_yn": "Enter y or n.",
        "invalid_mode": "Select 1 or 2.",
        "exit_profile_title": "Connection profile",
        "exit_profile_warn": (
            "If you do NOT save, data/config/.runtime_mode.json will be removed. "
            "Next launch will ask for language, online/offline, and Tor again."
        ),
        "exit_profile_ask": "Save connection profile (mode + Tor) for next run? (y/n): ",
        "exit_profile_kept": "Profile saved for next run.",
        "exit_profile_removed": "Profile removed — startup wizard will run next time.",
    },
    "ru": {
        "mode_title": "Режим работы",
        "mode_online": "1. Онлайн — живые запросы к API (ip-api, RIPE, WHOIS, passive DNS)",
        "mode_offline": "2. Оффлайн — только локальная БД ASN + intelligence cache",
        "mode_hint_online": "  Нужна сеть; API можно пустить через Tor.",
        "mode_hint_offline": "  Оффлайн: сверка с кэшем/БД; выбор Tor при старте пропускается.",
        "mode_prompt": "Выберите (1-2): ",
        "tor_title": "Анонимный egress (Tor)",
        "tor_ask": "Маршрутизировать HTTP(S) API FNkit через Tor? (y/n): ",
        "tor_skip": "Прямое подключение — Tor можно включить позже в меню 12.",
        "tor_bridges_ask": "Использовать obfs4-мосты? (если Tor блокируют) (y/n): ",
        "tor_bridges_yes": "  Добавьте строки Bridge в: {path}",
        "tor_bridges_link": "  https://bridges.torproject.org/",
        "tor_country_ask": "Страна выхода (необяз.). Примеры: de | de,us | {de},{us} | пусто=любая: ",
        "tor_country_hint": "  Коды ISO alpha-2; через запятую или в фигурных скобках Tor.",
        "tor_starting": "Запуск Tor…",
        "tor_ok": "Tor активен. API идут через SOCKS.",
        "tor_warn": "Tor настроен не полностью: {msg}",
        "tor_fail": "Не удалось включить Tor: {msg}",
        "invalid_yn": "Введите y или n.",
        "invalid_mode": "Выберите 1 или 2.",
        "exit_profile_title": "Профиль подключения",
        "exit_profile_warn": (
            "Если НЕ сохранять — файл data/config/.runtime_mode.json будет удалён. "
            "При следующем запуске снова спросят язык, онлайн/оффлайн и Tor."
        ),
        "exit_profile_ask": "Сохранить профиль (режим + Tor) для следующего запуска? (y/n): ",
        "exit_profile_kept": "Профиль сохранён для следующего запуска.",
        "exit_profile_removed": "Профиль удалён — при следующем запуске снова будет мастер настройки.",
    },
}


def msg(lang: str, key: str, **kwargs: Any) -> str:
    table = STRINGS.get(lang if lang in STRINGS else "en", STRINGS["en"])
    return table.get(key, key).format(**kwargs)


def is_offline() -> bool:
    return _OFFLINE


def is_online() -> bool:
    return not _OFFLINE


def _default_config() -> Dict[str, Any]:
    return {
        "mode": "online",
        "onboarding_complete": False,
        "tor": {
            "enabled": False,
            "use_bridges": False,
            "exit_countries": "",
        },
    }


def load_config() -> Dict[str, Any]:
    base = _default_config()
    try:
        if RUNTIME_MODE_FILE.exists():
            with open(RUNTIME_MODE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                if data.get("mode") in ("online", "offline"):
                    base["mode"] = data["mode"]
                base["onboarding_complete"] = bool(data.get("onboarding_complete"))
                tor_in = data.get("tor") if isinstance(data.get("tor"), dict) else {}
                tor = dict(base["tor"])
                tor["enabled"] = bool(tor_in.get("enabled"))
                tor["use_bridges"] = bool(tor_in.get("use_bridges"))
                tor["exit_countries"] = str(tor_in.get("exit_countries") or "")
                base["tor"] = tor
    except Exception:
        pass
    return base


def save_config(cfg: Dict[str, Any]) -> bool:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(RUNTIME_MODE_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def delete_config() -> bool:
    """Remove persisted runtime profile (next run shows onboarding wizard)."""
    try:
        if RUNTIME_MODE_FILE.is_file():
            RUNTIME_MODE_FILE.unlink()
        return True
    except OSError:
        return False


def has_saved_profile() -> bool:
    if not RUNTIME_MODE_FILE.is_file():
        return False
    return bool(load_config().get("onboarding_complete"))


def needs_onboarding() -> bool:
    if not RUNTIME_MODE_FILE.exists():
        return True
    return not load_config().get("onboarding_complete")


def normalize_tor_exit_countries(raw: str) -> str:
    """Convert user input to Tor ExitNodes value, e.g. ``{de},{us}``."""
    text = (raw or "").strip()
    if not text:
        return ""
    if "{" in text:
        codes = re.findall(r"\{([a-z]{2})\}", text.lower())
    else:
        codes = re.findall(r"[a-zA-Z]{2}", text.lower())
    codes = [c for c in codes if len(c) == 2]
    if not codes:
        return ""
    return "{" + "},{".join(dict.fromkeys(codes)) + "}"


def sync_offline_flag_from_disk() -> Dict[str, Any]:
    """Load config and set module offline flag (for CLI / non-interactive startup)."""
    cfg = load_config()
    global _OFFLINE
    _OFFLINE = cfg.get("mode") == "offline"
    return cfg


def apply_at_startup(*, colors: Optional[Dict[str, str]] = None) -> None:
    """Apply saved runtime profile (offline flag, Tor)."""
    import tor_transport

    cfg = sync_offline_flag_from_disk()

    if cfg.get("mode") == "offline":
        tor_transport.deactivate(persist=False)
        return

    tor = cfg.get("tor") or {}
    if not tor.get("enabled"):
        return

    exit_nodes = normalize_tor_exit_countries(str(tor.get("exit_countries") or ""))
    use_bridges = bool(tor.get("use_bridges")) or TOR_BRIDGES_FILE.is_file()
    ok, err = tor_transport.ensure_tor_daemon(use_bridges=use_bridges, exit_countries=exit_nodes or None)
    if not ok:
        c = colors or {}
        fail = c.get("fail", "")
        end = c.get("end", "")
        print(f"{fail}{err}{end}")
        return
    host, port = tor_transport.socks_endpoint()
    if not tor_transport.activate(socks_host=host, socks_port=port, persist=True):
        return
    v = tor_transport.verify_tor_circuit()
    if v.get("ok") and not v.get("is_tor") and use_bridges:
        c = colors or {}
        print(f"{c.get('warn', '')}SOCKS up but exit may not be Tor — check bridges.{c.get('end', '')}")


def _ask_yn(prompt: str, ask: Callable[[str], str], *, invalid: str) -> Optional[bool]:
    while True:
        try:
            ans = ask(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return None
        if ans in ("y", "yes", "д", "да"):
            return True
        if ans in ("n", "no", "н", "нет"):
            return False
        print(invalid)


def run_onboarding_interactive(
    *,
    lang: str = "en",
    print_fn: Optional[Callable[[str], None]] = None,
    input_fn: Optional[Callable[[str], str]] = None,
    colors: Optional[Dict[str, str]] = None,
) -> None:
    """Language → mode → (online) Tor setup; persist and apply."""
    global _OFFLINE
    import tor_transport

    out = print_fn or print
    ask = input_fn or input
    cfg = load_config()

    out("")
    out(msg(lang, "mode_title"))
    out(msg(lang, "mode_online"))
    out(msg(lang, "mode_hint_online"))
    out(msg(lang, "mode_offline"))
    out(msg(lang, "mode_hint_offline"))

    mode = None
    while mode is None:
        try:
            choice = ask(msg(lang, "mode_prompt")).strip()
        except (EOFError, KeyboardInterrupt):
            cfg["mode"] = "offline"
            cfg["onboarding_complete"] = True
            save_config(cfg)
            _OFFLINE = True
            return
        if choice == "1":
            mode = "online"
        elif choice == "2":
            mode = "offline"
        else:
            out(msg(lang, "invalid_mode"))

    cfg["mode"] = mode
    _OFFLINE = mode == "offline"

    if mode == "offline":
        cfg["tor"] = {"enabled": False, "use_bridges": False, "exit_countries": ""}
        cfg["onboarding_complete"] = True
        save_config(cfg)
        tor_transport.deactivate(persist=True)
        return

    out("")
    out(msg(lang, "tor_title"))
    use_tor = _ask_yn(msg(lang, "tor_ask"), ask, invalid=msg(lang, "invalid_yn"))
    if use_tor is None:
        cfg["onboarding_complete"] = True
        save_config(cfg)
        return

    if not use_tor:
        out(msg(lang, "tor_skip"))
        cfg["tor"] = {"enabled": False, "use_bridges": False, "exit_countries": ""}
        cfg["onboarding_complete"] = True
        save_config(cfg)
        tor_transport.deactivate(persist=True)
        return

    use_bridges = _ask_yn(msg(lang, "tor_bridges_ask"), ask, invalid=msg(lang, "invalid_yn"))
    if use_bridges is None:
        cfg["onboarding_complete"] = True
        save_config(cfg)
        return
    if use_bridges:
        out(msg(lang, "tor_bridges_yes", path=TOR_BRIDGES_FILE))
        out(msg(lang, "tor_bridges_link"))

    try:
        country_raw = ask(msg(lang, "tor_country_ask")).strip()
    except (EOFError, KeyboardInterrupt):
        country_raw = ""
    out(msg(lang, "tor_country_hint"))
    exit_nodes = normalize_tor_exit_countries(country_raw)

    cfg["tor"] = {
        "enabled": True,
        "use_bridges": bool(use_bridges),
        "exit_countries": exit_nodes,
    }
    cfg["onboarding_complete"] = True
    save_config(cfg)

    c = colors or {}
    ok_c = c.get("ok", "")
    fail_c = c.get("fail", "")
    warn_c = c.get("warn", "")
    end = c.get("end", "")

    out(msg(lang, "tor_starting"))
    ok, err = tor_transport.ensure_tor_daemon(
        use_bridges=bool(use_bridges) or TOR_BRIDGES_FILE.is_file(),
        exit_countries=exit_nodes or None,
    )
    if not ok:
        out(f"{fail_c}{msg(lang, 'tor_fail', msg=err)}{end}")
        return
    host, port = tor_transport.socks_endpoint()
    if tor_transport.activate(socks_host=host, socks_port=port, persist=True):
        v = tor_transport.verify_tor_circuit()
        if v.get("is_tor"):
            out(f"{ok_c}{msg(lang, 'tor_ok')}{end}")
        else:
            out(f"{warn_c}{msg(lang, 'tor_warn', msg='exit not confirmed as Tor')}{end}")
    else:
        out(f"{fail_c}{msg(lang, 'tor_fail', msg='SOCKS unreachable')}{end}")


def prompt_exit_profile_disposition(
    *,
    lang: str = "en",
    print_fn: Optional[Callable[[str], None]] = None,
    input_fn: Optional[Callable[[str], str]] = None,
    colors: Optional[Dict[str, str]] = None,
) -> None:
    """
    On interactive exit: ask whether to keep ``.runtime_mode.json``.
    ``y`` = keep file; ``n`` = delete (wizard runs again next launch).
    """
    import sys

    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return
    if not has_saved_profile():
        return

    out = print_fn or print
    ask = input_fn or input
    c = colors or {}
    warn = c.get("warn", "")
    ok = c.get("ok", "")
    end = c.get("end", "")

    out("")
    out(msg(lang, "exit_profile_title"))
    out(f"{warn}{msg(lang, 'exit_profile_warn')}{end}")

    while True:
        try:
            ans = ask(msg(lang, "exit_profile_ask")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            save_config(load_config())
            return
        if ans in ("y", "yes", "д", "да"):
            save_config(load_config())
            out(f"{ok}{msg(lang, 'exit_profile_kept')}{end}")
            return
        if ans in ("n", "no", "н", "нет"):
            delete_config()
            out(f"{warn}{msg(lang, 'exit_profile_removed')}{end}")
            return
        out(msg(lang, "invalid_yn"))
