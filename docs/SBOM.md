# SBOM (Software Bill of Materials)

## Назначение

SBOM описывает **все внешние зависимости** `FieldNet Kit (fnkit)`: рантайм Python, pip-пакеты, системные CLI и сетевые сервисы. Источник правды — [`dependencies.manifest.json`](../dependencies.manifest.json); артефакты SBOM **генерируются** и не редактируются вручную.

## Файлы

| Файл | Формат | Описание |
|------|--------|----------|
| `dependencies.manifest.json` | JSON | Манифест: scope, purl, лицензии, модули, проверки, команды установки по ОС |
| `sbom.cdx.json` | CycloneDX 1.5 | Для CI, Dependabot, инструментов supply-chain |
| `sbom.spdx.json` | SPDX 2.3 | Альтернативный обмен с compliance-инструментами |
| `requirements-dns.txt` | pip | Опционально: DNS (`dnspython`) |
| `requirements-optional.txt` | pip | Опционально: MaxMind / IP2Location |

## Генерация

```bash
python3 tools/generate_sbom.py
```

CI на Python 3.10 проверяет, что `sbom.cdx.json` и `sbom.spdx.json` совпадают с манифестом (`git diff --exit-code`).

После изменения `dependencies.manifest.json` или `requirements-*.txt` всегда перегенерируйте SBOM и коммитьте оба JSON.

## Группы зависимостей (feature groups)

| Группа | Состав | Нужна для |
|--------|--------|-----------|
| `core` / `minimal` | Python, whois, ping, ip-api, RIR WHOIS | Проверка IP/ASN |
| `diagnostics` | traceroute/tracert, nslookup | Меню 4, инструменты после IP |
| `scan` | nmap | nmap в подменю |
| `pcap` | tcpdump, tshark | PCAP меню 4 |
| `dns` | dnspython, crt.sh, tshark | Меню 10 |
| `enrichment` | geoip2, IP2Location | Меню 7 |
| `owasp` | amass, nettacker | Меню 11 |
| `speedtest` | speed.cloudflare.com | Speed-test |
| `full` | все группы | Полный «швейцарский нож» |

## Проверка зависимостей

```bash
# Минимум для запуска
python3 scripts/check_deps.py --group minimal

# Перед DNS
python3 scripts/check_deps.py --group dns

# JSON для CI / мониторинга
python3 scripts/check_deps.py --group full --json

# Подсказки установки из манифеста
python3 scripts/check_deps.py --group owasp --hints
```

Из FieldNet Kit:

```bash
python3 fnkit.py --check-deps
python3 fnkit.py --check-deps --check-deps-group dns
```

## Автоматическая установка

### macOS / Linux

```bash
chmod +x scripts/install-deps.sh
./scripts/install-deps.sh minimal    # Python, whois, ping
./scripts/install-deps.sh full       # всё возможное через brew/apt + pip
./scripts/install-deps.sh dns
./scripts/install-deps.sh owasp
```

### Windows (PowerShell)

```powershell
.\scripts\install-deps.ps1 -Profile minimal
.\scripts\install-deps.ps1 -Profile full
.\scripts\install-deps.ps1 -Profile dns
```

Используются **winget** / **choco**, если доступны; иначе выводятся подсказки из манифеста.

## CycloneDX: свойства установки

В `sbom.cdx.json` у компонентов могут быть properties вида:

- `fnkit:featureGroup` — группа функций
- `fnkit:install:macos:brew` — пример команды brew
- `fnkit:install:linux:apt` — пакеты apt
- `fnkit:install:windows:winget` — id winget

Это связывает SBOM с воспроизводимой установкой на разных ОС.

## Лицензии сторонних компонентов

| Компонент | Лицензия (типично) |
|-----------|-------------------|
| FieldNet Kit (`fieldnetkit`) | MIT |
| dnspython | ISC |
| geoip2 | Apache-2.0 |
| IP2Location (pip) | MIT |
| Amass | Apache-2.0 |
| Nettacker | AGPL-3.0 |
| Системные CLI / сервисы | NOASSERTION в SBOM (см. поставщика ОС/API) |

OWASP: [docs/OWASP_THIRD_PARTY.md](OWASP_THIRD_PARTY.md).

## Обновление манифеста

1. Добавьте запись в `dependencies.manifest.json` (`id`, `purl`, `scope`, `check`, `install`, `modules`).
2. При pip — строку в `requirements-*.txt`.
3. `python3 tools/generate_sbom.py`
4. `python3 scripts/check_deps.py --group <ваша_группа>`
5. Обновите README и при необходимости `install-deps.sh` / `install-deps.ps1`.
