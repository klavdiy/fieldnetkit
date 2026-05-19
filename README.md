# FieldNet Kit (FNkit)

**FieldNet Kit** — portable network intelligence workbench: проверка доверия к IP/ASN, DNS-граф, сетевая диагностика, PCAP и OWASP-проверки с одной машины.

| | |
|---|---|
| Полное название | **FieldNet Kit** |
| Сокращение | **FNkit** |
| CLI / файлы | **`fnkit`** (`fnkit.py`, `fnkit.sh`, `fnkit.ps1`) |

> Ранее репозиторий назывался *ip_checker*. Репозиторий на GitHub: **`fieldnetkit`** (`github.com/klavdiy/fieldnetkit`).

---

## Навигация

<details open>
<summary><strong>Развернуть / свернуть оглавление</strong></summary>

### Старт

| | |
|---|---|
| [Быстрый старт](#быстрый-старт) | Установка, `./fnkit.sh`, первый запуск |
| [Экран при запуске](#экран-при-запуске) | Рамка с egress IP |
| [Структура проекта](#структура-проекта) | Файлы и каталоги |
| [Зависимости](#зависимости) | Группы, `check_deps`, install-скрипты |

### Главное меню TUI (`0`–`11`)

Сводная таблица: [Главное меню — обзор](#главное-меню--обзор)

| № | Раздел | Что внутри |
|---|--------|------------|
| [**0**](#пункт-0--выход) | Выход | Завершение программы |
| [**1**](#пункт-1--проверить-ip) | IP | Гео, mismatch, WHOIS, abuse, [инструменты после IP](#меню-после-проверки-ip) |
| [**2**](#пункт-2--диапазон-ip) | Диапазон | До 10 IP, сводка, сохранение отчёта |
| [**3**](#пункт-3--asn-оператора) | ASN | Пулы из БД или разведка неизвестного ASN |
| [**4**](#пункт-4--диагностика-сети) | Диагностика | Speed-test, trace, PCAP — см. [подменю 4](#подменю-4--диагностика-сети) |
| [**5**](#пункт-5--сетевые-интерфейсы) | NIC | Список интерфейсов ОС |
| [**6**](#пункт-6--обновить-базу) | База | Метаданные `asn_database.json` |
| [**7**](#пункт-7--api-ключи-обогащения) | Enrichment | MaxMind, IP2Location |
| [**8**](#пункт-8--язык) | Язык | RU / EN |
| [**9**](#пункт-9--справка) | Справка | Краткая помощь в TUI |
| [**10**](#пункт-10--dns-анализ) | DNS | Граф, crt.sh, HTML — см. [подменю 10](#подменю-10--dns) |
| [**11**](#пункт-11--owasp-toolkit) | OWASP | Headers, Amass, Nettacker, WSTG |

#### Подменю 4 — диагностика сети

| Подп. | Раздел |
|-------|--------|
| [4.1](#41--speed-test) | Speed-test |
| [4.2](#42--монитор-маршрута-trace-monitor) | Монитор маршрута |
| [4.3](#43--воспроизведение-trace) | Replay JSON |
| [4.4](#44--захват-pcap) | Захват PCAP |
| [4.5](#45--просмотр-pcap) | Просмотр PCAP |

#### Подменю 10 — DNS

| Подп. | Раздел |
|-------|--------|
| [10.1](#пункт-101--crawl) | Crawl домена |
| [10.2](#пункт-102--открыть-сессию) | Открыть сессию |
| [10.3](#пункт-103--html-граф) | HTML-граф |
| [10.4](#пункт-104--сравнение-резолверов) | Сравнение резолверов |
| [10.5](#пункт-105--pcap--dns) | PCAP → DNS |

### CLI и данные

| | |
|---|---|
| [CLI (все режимы)](#cli-все-режимы) | Правила запуска, deps, Actions, PowerShell |
| [Справочник CLI — все флаги](#справочник-cli--все-флаги) | Полная таблица аргументов |
| [Форматы JSON-файлов](#форматы-json-файлов) | `scan_results`, trace, dns, owasp, база |

### Справка и проект

| | |
|---|---|
| [Политика источников и карантин](#политика-источников-и-карантин) | whois vs ip-api, quarantine |
| [Устранение неполадок](#устранение-неполадок) | Типичные ошибки |
| [SBOM и CI](#sbom-и-ci) | Supply chain, GitHub Actions |
| [Сообщество](#сообщество) | Contributing, Security |
| [Лицензия](#лицензия) | MIT |

**Внешняя документация:** [docs/SBOM.md](docs/SBOM.md) · [docs/OWASP_INTEGRATION.md](docs/OWASP_INTEGRATION.md) · [docs/OWASP_THIRD_PARTY.md](docs/OWASP_THIRD_PARTY.md)

</details>

---

## Быстрый старт

```bash
chmod +x fnkit.sh scripts/install-deps.sh
./scripts/install-deps.sh minimal   # опционально: полный набор
./fnkit.sh
```

```bash
python3 fnkit.py -h
python3 fnkit.py -i 8.8.8.8
```

Windows:

```powershell
.\scripts\install-deps.ps1 -Profile minimal
.\fnkit.ps1 -i 8.8.8.8
```

При первом интерактивном запуске выберите язык (**English** / **Русский**). Сохраняется в `.language_config`.

При старте в рамке показывается **ваш публичный egress IP** (через ip-api) — baseline «откуда идёт трафик».

### Главное меню (пример)

```text
============================================================
FieldNet Kit (FNkit)
============================================================

1. Проверить IP адрес
2. Проверить диапазон IP
3. Проверить ASN оператора
4. Диагностика сети (трассировка / speed test)
5. Список сетевых интерфейсов (параметры NIC)
6. Обновить базу
7. Настроить API ключи обогащения
8. Выбрать язык
9. Справка
10. DNS-анализ (граф / поддомены)
11. OWASP (Amass / Nettacker / headers / WSTG)
0. Выход

Введите номер пункта меню (0–11) и нажмите Enter.
Выберите опцию (0-11):
```

---

## Экран при запуске

Перед меню (и перед CLI с геопроверкой) печатается рамка egress:

```text
+==========================================================+
| Public IP: 203.0.113.45                                    |
| Location: Berlin, Germany                                |
| ISP: Example ISP GmbH                                    |
| ASN: AS3320                                                |
+==========================================================+
```

Если ip-api недоступен:

```text
| Could not detect public IP (offline or API error).       |
```

---

## Структура проекта

```text
fieldnetkit/
├── fnkit.py                 # Главное приложение
├── fnkit.sh / fnkit.ps1     # Обёртки запуска
├── asn_database.json        # Локальная модель ASN / пулов / expected country
├── network_diag.py          # Speed-test, trace monitor, NIC list
├── pcap_diag.py             # PCAP capture / show / verify
├── dns_diag.py              # DNS-граф, crt.sh, HTML export
├── owasp_toolkit.py         # Secure Headers, Amass, Nettacker, WSTG
├── dependencies.manifest.json
├── sbom.cdx.json / sbom.spdx.json
├── scripts/                 # check_deps, install-deps
├── docs/                    # SBOM, OWASP
├── trace_sessions/          # JSON трасс (gitignore)
├── dns_sessions/ dns_graph/ # DNS (gitignore)
├── owasp_sessions/          # OWASP (gitignore)
├── network capture/         # PCAP (gitignore)
├── scan_results.json        # при -s/--save
├── .language_config
└── .enrichment_config.json  # ключи MaxMind / IP2Location
```

---

## Зависимости

Полный список: [`dependencies.manifest.json`](dependencies.manifest.json), SBOM: [`docs/SBOM.md`](docs/SBOM.md).

| Группа | Нужно для | Примеры |
|--------|-----------|---------|
| **core** / minimal | Меню 1–3, 6 | Python 3.10+, `whois`, `ping`, ip-api |
| **diagnostics** | Меню 4, инструменты после IP | `traceroute`/`tracert`, `nslookup` |
| **scan** | nmap после IP | `nmap` |
| **pcap** | Меню 4.4–4.5 | `tcpdump`, `tshark` |
| **dns** | Меню 10 | `pip install dnspython`, `tshark` |
| **enrichment** | Меню 7 | `geoip2`, `IP2Location` |
| **owasp** | Меню 11 | `amass`, Nettacker (AGPL) |

```bash
python3 scripts/check_deps.py --group minimal
python3 fnkit.py --check-deps --check-deps-hints
./scripts/install-deps.sh full
pip install -r requirements-dns.txt -r requirements-optional.txt
```

---

## Главное меню — обзор

Цифра в консоли = номер пункта. **`0`** — выход.

| № | Название | Кратко |
|---|----------|--------|
| **1** | Проверить IP | Гео + сверка с `asn_database.json`, WHOIS/abuse, опционально инструменты |
| **2** | Диапазон IP | До **10** IP подряд (интерактивно) |
| **3** | ASN | Проверка пулов из БД или разведка неизвестного ASN |
| **4** | Диагностика сети | Speed-test, trace monitor, PCAP |
| **5** | Интерфейсы | Список NIC из ОС |
| **6** | Обновить базу | Метаданные БД (см. ограничения) |
| **7** | Enrichment keys | MaxMind / IP2Location |
| **8** | Язык | RU / EN |
| **9** | Справка | Краткие подсказки в TUI |
| **10** | DNS | Граф, crt.sh, HTML, PCAP→DNS |
| **11** | OWASP | Headers, Amass, Nettacker, WSTG |
| **0** | Выход | Завершение без сохранения состояния (кроме уже записанных `.language_config` / сессий) |

---

## Пункт 0 — Выход

Введите **`0`** в главном меню. Корректное завершение цикла; несохранённые отчёты (если вы ответили `n` на «Save report») не попадают в `scan_results.json`.

---

## Пункт 1 — Проверить IP

### Назначение

Сверить **фактическую** геолокацию IP (ip-api) с **ожидаемой** страной из локальной базы для совпавшего ASN/пула. Полезно для: VPN/CDN, ошибок CMDB, abuse-эскалации, полевой проверки «тот ли это оператор».

### Как пользоваться (интерактивно)

1. Главное меню → **`1`**
2. Введите IPv4/IPv6 (например `8.8.8.8`). **`0`** — отмена
3. Читайте вывод: match / mismatch / «не в базе»
4. При mismatch — предложение **переклассифицировать** ASN (`y`/`n`)
5. Показывается **abuse** из WHOIS (с дораскрытием handle)
6. Опционально — **меню инструментов** (nmap, traceroute, nslookup, Secure Headers)

### Порядок полей в отчёте

1. Страна (ожидаемая / фактическая)  
2. ASN  
3. Пул (CIDR)  
4. Провайдер  
5. Abuse-контакт  

### Пример вывода (match)

```text
Checking IP: 8.8.8.8
✓ Matches expected location
  Expected Country: US | Actual Country: US
  ASN: AS15169
  Pool: 8.0.0.0/8
  Provider: Google LLC
Abuse / complaints: abuse@google.com
```

### Пример вывода (mismatch)

```text
Checking IP: 195.20.1.1
✗ MISMATCH DETECTED!
  Expected Country: RU (Russia) | Actual Country: DE (Germany)
  ASN: AS12389
  Pool: 83.0.0.0/8
  Provider: Example Telecom
Abuse / complaints: abuse@example.com

MISMATCH FOUND!
Would you like to reclassify this ASN? (y/n):
```

При `y` — шаги переклассификации (верификация WHOIS, обновление `expected_country`, повторная проверка). При конфликте whois ≠ ip-api:

```text
⚠ Conflict quarantined: WHOIS and ip-api disagree. No DB write performed.
```

### Интерактивный сценарий

```text
Выберите опцию (0-11): 1
IP: 8.8.8.8
… (отчёт) …
Save this report to scan_results.json? (y/n): n

Additional network tools (checked IP): 8.8.8.8
1. nmap (run with -A -T4)
…
Select (0-4): 0
```

### CLI

```bash
./fnkit.sh -i 83.1.1.1
python3 fnkit.py -i 195.20.1.1 --auto-reclass
python3 fnkit.py -i 195.20.1.1 --auto-reclass --quiet -s
```

| Флаг | Описание |
|------|----------|
| `-i` / `--ip` | Один адрес |
| `-s` / `--save` | Запись в `scan_results.json` |
| `--auto-reclass` | Без интерактивных `y/n` при переклассификации |
| `--quiet` | Только с `--auto-reclass` — минимум вывода |

### Неизвестный IP

Если IP нет ни в одном пуле БД:

```text
⚠ IP not found in any ASN pool
No local data found, requesting WHOIS...
Checking WHOIS data...

============================================================
WHOIS Information
============================================================
Detected ASN: AS15169
Detected Provider: Google LLC
Detected Country: US (United States)
Pool: 8.0.0.0/8
IP: 8.8.8.8

------------------------------------------------------------
Geo enrichment comparison
  Primary: US (United States)
  MaxMind: no data (API KEY required)
  IP2Location: no data (API KEY required)

Add this information to the database? (y/n):
```

---


## Пункт 2 — Диапазон IP

### Назначение

Пакетная проверка нескольких адресов подряд из диапазона.

### Как пользоваться

1. Меню → **`2`**
2. **Start IP** и **End IP**
3. Сканируется до **10** адресов от начала диапазона (шаг +1)
4. Общая **сводка** и предложение сохранить отчёт

### Пример вывода

```text
Start IP: 10.0.0.1
End IP: 10.0.0.5

Scanning 10 IPs...

Checking IP: 10.0.0.1
…
Checking IP: 10.0.0.5

============================================================
SCAN SUMMARY
============================================================
Total IPs checked: 5
Matches (location correct): 3
Mismatches (location incorrect): 2

Save this report to scan_results.json? (y/n):
```

### CLI

```bash
./fnkit.sh -r 83.0.0.1 83.0.0.255 --max-ips 20 -s
python3 fnkit.py --range 10.0.0.1 10.0.0.50 --max-ips 256
```

| Флаг | По умолчанию | Описание |
|------|--------------|----------|
| `-r` START END | — | Диапазон |
| `--max-ips` | 256 | Лимит в CLI (в меню жёстко 10) |

> В интерактивном меню лимит **10 IP** задан в коде; в CLI — `--max-ips`.

---

## Пункт 3 — ASN оператора

### Назначение

Проверить оператора целиком: если ASN есть в БД — пробные IP из первых **трёх** пулов; если нет — WHOIS aut-num, маршруты (RIPE), выборочная геопроверка, добавление в БД.

### Как пользоваться

1. Меню → **`3`**
2. Введите `AS12389` или `12389`
3. **В базе:** owner, expected country, проверка `.network_address` каждого из ≤3 пулов
4. **Не в базе:** WHOIS, семплы IP, опционально добавление ASN

### Пример (ASN в базе)

```text
ASN (e.g., AS12389 or 12389): AS12389

Checking ASN: AS12389
  Owner: TalkTalk
  Expected Country: GB (United Kingdom)
Checking IP: 83.0.0.0
…
============================================================
SCAN SUMMARY
…
```

### Пример (ASN не в базе)

```text
ASN is not in the local database — querying WHOIS for this autonomous system…
WHOIS (aut-num)
AS name: EXAMPLE-AS
Sampling up to 8 IP(s) from WHOIS routes for geo check…
Add this ASN to the local database using the data above? (y/n):
```

### CLI

```bash
./fnkit.sh -a AS12389 -s
python3 fnkit.py --asn 20485 --save
```

---

## Пункт 4 — Диагностика сети

#### Подменю 4 — диагностика сети

Подменю (только в **TTY**):

| Подп. | Функция |
|-------|---------|
| **1** | Speed-test (ICMP + Cloudflare HTTP) |
| **2** | Монитор задержки по хопам |
| **3** | Воспроизведение JSON-сессии trace |
| **4** | Захват PCAP (`tcpdump`) |
| **5** | Просмотр PCAP (`tshark` / `tcpdump -r`) |
| **0** | Назад |

### 4.1 — Speed-test

**Что делает:** медиана RTT ping к `1.1.1.1`, ориентировочный download/upload через `speed.cloudflare.com`.

```bash
python3 fnkit.py --speed-test
```

**Пример вывода (4.1):**

```text
Channel check (Cloudflare HTTP, approximate)

ICMP ping median to 1.1.1.1: 12.4 ms (from 5 probes)
Download: ~85.2 Mbps (9.54 MB in 0.89 s)
Upload: ~42.1 Mbps (3.81 MB in 0.72 s)
Results are approximate; ISP routing may vary.
```

### 4.2 — Монитор маршрута (trace monitor)

**Что делает:**

1. `traceroute`/`tracert` до цели → список hop IPv4  
2. Периодический `ping` по каждому хопу  
3. В **TTY** — таблица в одном окне; без TTY — накопительный лог  
4. Клавиши: **`p`** пауза, **`q`** или **Ctrl+C** стоп  
5. После остановки — предложение сохранить JSON в `trace_sessions/` (формат `fnkit_trace_v1`; читаются и старые `ip_checker_trace_v1`)

**Пример (меню):** `4` → `2` → хост `8.8.8.8`

```bash
python3 fnkit.py --trace-monitor 8.8.8.8 --trace-interval 2.5 --trace-max-hops 20
```

| Флаг | Default | Описание |
|------|---------|----------|
| `--trace-monitor HOST` | — | Цель |
| `--trace-interval` | 3 | Сек между раундами ping |
| `--trace-max-hops` | 30 | Хопы traceroute |
| `--trace-rediscover` | 45 | Полный traceroute каждые N раундов; `0` — выкл |

**Пример вывода (4.2, фрагмент TTY-дашборда):**

```text
Route latency monitor → 8.8.8.8
Hop RTT / loss by hop  (× = timeout / loss in sparkline)
 interval 3.0s  |  rediscover every 45 rounds
Round 12
 #   Address         RTT ms   Loss    Trend (RTT)
 1   192.168.1.1     1.2      0%      ▂▃▅
 2   10.0.0.1        3.8      0%      ▃▄▅
 3   203.0.113.1     8.1      0%      ▅▆▇
 …
Keys: p pause · q stop
```

После `q` — диалог сохранения:

```text
Session stopped.
Save this session (12 rounds) to JSON for later replay? (y/n): y
File path [Enter = trace_sessions/trace_8.8.8.8_20260519T120000Z.json]:
Saved: trace_sessions/trace_8.8.8.8_20260519T120000Z.json
```

### 4.3 — Воспроизведение trace

1. `4` → `3` → выбор файла из `trace_sessions/` или путь  
2. После просмотра: **`r`** — повтор, **`q`** — назад

```bash
python3 fnkit.py --trace-replay trace_sessions/trace_8.8.8.8_20260510.json --trace-replay-delay 0
```

### 4.4 — Захват PCAP

1. `4` → `4`  
2. Интерфейс (`en0`, `eth0`…), путь `.pcap` (Enter = `network capture/capture_YYYYMMDD_HHMMSS.pcap`)  
3. Длительность (сек), опционально **BPF** (`tcp port 443`)  
4. Часто нужны **`sudo`** / разрешения macOS

```bash
sudo python3 fnkit.py --pcap-capture en0 --pcap-out "./network capture/test.pcap" \
  --pcap-seconds 15 --pcap-filter 'tcp port 443'
```

### 4.5 — Просмотр PCAP

Проверка заголовка (classic/PCAPNG), SHA-256, список кадров; hex по запросу.

```bash
python3 fnkit.py --pcap-show "./network capture/test.pcap" --pcap-max-packets 120 --pcap-hex
```

**Пример вывода (4.4, после захвата):**

```text
PCAP file check
  Path: network capture/capture_20260519_120000.pcap
  Format: classic PCAP (LE microsecond)
  SHA-256: a1b2c3…
  Packets (approx): 1240
```

**Пример вывода (4.5, список кадров):**

```text
   1  0.000000 192.168.1.10 → 8.8.8.8  DNS Standard query A example.com
   2  0.012340 8.8.8.8 → 192.168.1.10  DNS Standard query response A 93.184.216.34
 …
```

---

## Пункт 5 — Сетевые интерфейсы

### Назначение

Список NIC из ОС: имя, тип (эвристика), up/down, MTU, MAC, IPv4/IPv6 — выбор интерфейса для PCAP или отладка маршрута.

### Как пользоваться

Главное меню → **`5`** — однократный вывод, возврат в меню.

Зависимости: только Python (модуль `network_diag`).

**Пример вывода:**

```text
Interface          Kind        State   MTU    MAC                 IPv4
--------------------------------------------------------------------------------
lo0                loopback    up      16384  —                   127.0.0.1
en0                ethernet    up      1500   aa:bb:cc:dd:ee:ff   192.168.1.10
utun4              tunnel      up      1380   —                   10.8.0.2
```

Используйте имя из колонки **Interface** в меню **4.4** (PCAP capture).

---

## Пункт 6 — Обновить базу

### Назначение

Обслуживание **метаданных** `asn_database.json`: `last_updated`, счётчики ASN/пулов, сброс напоминаний.

### Автоматическое напоминание (30 / 7 дней)

- Если `last_updated` старше **30 дней** — при старте спрос «обновить?»  
- **`y`** — обновление метаданных  
- **`n`** — отложить на **7 дней** (`next_update_prompt_after`)

> **Важно:** пункт **не** подтягивает префиксы из RIR автоматически. ASN/пулы по-прежнему ведутся вручную или через flow переклассификации / unknown IP.

### Как пользоваться

Меню → **`6`** — сразу выполняется `perform_database_update`.

**Пример вывода:**

```text
Updating database...
Database updated
```

При автопроверке при старте (если `last_updated` > 30 дней):

```text
Database update check is required - last check was 45 days ago. Update now? (y/n):
```

---

## Пункт 7 — API ключи обогащения

### Назначение

Сравнение гео **ip-api** (primary) с **MaxMind** и **IP2Location** при наличии ключей. Ключи в `.enrichment_config.json` (не коммитить).

### Подменю

| № | Провайдер | Формат ключа |
|---|-----------|--------------|
| 1 | MaxMind | `ACCOUNT_ID:LICENSE_KEY` |
| 2 | IP2Location | API key |
| 0 | Назад | |

```bash
pip install -r requirements-optional.txt
```

Сравнение выводится в flow **unknown IP** (пункт 1) после WHOIS.

**Интерактивный сценарий:**

```text
Выберите опцию (0-11): 7
1. MaxMind
2. IP2Location
0. Back
Выберите (0-2): 1
Enter MaxMind key as ACCOUNT_ID:LICENSE_KEY (or 0 back): 123456:AbCdEfGhIjKlMnOp
Saved.
Configure another service key? (y/n): n
```

**Пример сравнения (после настройки ключей):**

```text
Geo enrichment comparison
  Primary: US (United States)
  MaxMind: US (United States)
  IP2Location: US (United States)
```

---

## Пункт 8 — Язык

Меню → **`8`** → `1` English / `2` Русский.

Сохраняется в `.language_config`. Влияет на все строки TUI и подмодули.

CLI-only режимы (только `--dns`, `--trace-*`, `--owasp-*`) при отсутствии конфига используют **en**.

---

## Пункт 9 — Справка

Встроенная краткая справка в TUI (дублирует структуру README в сжатом виде).

**Как открыть:** главное меню → **`9`**.

**Содержит:** описание пунктов 1–11, напоминание про mismatch/reclassify, блок **CLI** (`--speed-test`, `--trace-*`, `--pcap-*`, `--dns`, `--owasp-*`, `--check-deps`), ссылки на `./scripts/install-deps.sh` и `docs/SBOM.md`.

Полная документация с примерами вывода — этот **README**.

---

## Пункт 10 — DNS-анализ

Требуется: `pip install -r requirements-dns.txt` (`dnspython`).

#### Подменю 10 — DNS

### Подменю DNS

| № | Действие |
|---|----------|
| **1** | Crawl от seed-домена (BFS A/AAAA/CNAME/MX/NS/TXT/SOA) |
| **2** | Сводка сохранённой сессии |
| **3** | Экспорт HTML-графа (`dns_graph/`, vis-network) |
| **4** | Сравнение резолверов: system / 1.1.1.1 / 8.8.8.8 |
| **5** | Crawl с seed из DNS-имён в PCAP (`tshark`) |
| **0** | Назад |

### Пункт 10.1 — Crawl

1. Домен, например `example.com`  
2. **crt.sh?** `y` — пассивные поддомены  
3. Путь к **wordlist** (Enter — без брута)  
4. Сводка: домены, IP, рёбра, метрики (shared IP, CNAME loops…)  
5. Сохранить JSON в `dns_sessions/` (`fnkit_dns_v1`)

**Пример вывода (10.1):**

```text
DNS crawl from seed: example.com
Fetching passive subdomains (crt.sh)…
crt.sh: 42 unique names
Crawl finished: 87 domains, 34 IPs, 156 edges (depth ≤ 4)

Graph metrics
  Max BFS depth: 3
  CNAME loops detected: 0
  External NS hosts: 2
  Domains sharing an IP (top groups):
    93.184.216.34 → www.example.com, example.com
Save session JSON? (y/n): y
Session saved: dns_sessions/example_com_20260519T120000Z.json
```

### Пункт 10.2 — Открыть сессию

Меню **10** → **2** → номер файла из `dns_sessions/` или полный путь → таблица узлов и метрики.

### Пункт 10.3 — HTML-граф

Меню **10** → **3** → выбор сессии → файл в `dns_graph/`. Откройте `.html` в браузере (vis-network).

### Пункт 10.4 — Сравнение резолверов

```text
Выберите (0-5): 4
Domain (e.g. example.com): example.com
  A/AAAA agree across system, 1.1.1.1, 8.8.8.8
```

При расхождении:

```text
  system: ['1.2.3.4']  vs  1.1.1.1: ['5.6.7.8']
```

### Пункт 10.5 — PCAP → DNS

Нужен `tshark`. Имена из PCAP добавляются в очередь crawl.

### CLI DNS

```bash
python3 fnkit.py --dns example.com --dns-crtsh --dns-depth 4 --dns-save
python3 fnkit.py --dns example.com --dns-wordlist ./subdomains.txt --dns-qps 10
python3 fnkit.py --dns-replay dns_sessions/example_com_*.json
python3 fnkit.py --dns-replay dns_sessions/sess.json --dns-export dns_graph/graph.html
python3 fnkit.py --dns-pcap "network capture/cap.pcap" --dns example.com --dns-save
```

| Флаг | Default | Описание |
|------|---------|----------|
| `--dns` | — | Seed-домен |
| `--dns-depth` | 4 | Глубина BFS |
| `--dns-max-domains` | 500 | Лимит доменов |
| `--dns-crtsh` | off | crt.sh |
| `--dns-wordlist` | — | Файл поддоменов |
| `--dns-qps` | 20 | Rate limit |
| `--dns-save` | — | JSON в `dns_sessions/` |
| `--dns-replay` | — | Сводка сессии |
| `--dns-export` | — | HTML-граф |
| `--dns-pcap` | — | Имена из PCAP → crawl |

---

## Пункт 11 — OWASP toolkit

См. [docs/OWASP_THIRD_PARTY.md](docs/OWASP_THIRD_PARTY.md) (лицензии, authorized use).

### Подменю OWASP

| № | Действие |
|---|----------|
| **1** | Guided pipeline (контекст → headers → Amass → Nettacker? → WSTG) |
| **2** | Secure Headers (встроенный HTTP) |
| **3** | Amass passive (нужен `amass` в PATH) |
| **4** | Nettacker port_scan (AGPL, отдельная установка) |
| **5** | WSTG checklist (только ссылки) |
| **6** | Список / просмотр `owasp_sessions/*.json` |
| **7** | Legal notice |
| **0** | Назад |

Перед пунктами 1–6 (кроме 7) — **disclaimer** authorized use.

После проверки IP в меню **11** подставляется контекст **IP** из последней проверки.

### CLI OWASP

```bash
python3 fnkit.py --owasp-headers https://example.com
python3 fnkit.py --owasp-amass example.com --owasp-save
python3 fnkit.py --owasp-wstg
python3 fnkit.py --owasp-pipeline --owasp-domain example.com --owasp-ip 203.0.113.10 --owasp-save
python3 fnkit.py --owasp-pipeline --owasp-domain example.com --owasp-nettacker-run --owasp-save
```

**Пример вывода (11.2 Secure Headers):**

```text
Secure Headers report
URL: https://example.com/
  [+] strict-transport-security: max-age=31536000; includeSubDomains
  [+] x-content-type-options: nosniff
  [-] content-security-policy (severity: high)
  [-] x-frame-options (severity: medium)
```

**Пример (11.5 WSTG):**

```text
WSTG checklist (links only)
  WSTG-INFO-02 Fingerprint web server and frameworks …
    https://owasp.org/…/02-Fingerprint_Web_Server
  WSTG-CONF-02 Review security headers and transport …
```

**Пример (11.1 pipeline):** последовательно headers → опционально Amass → WSTG → JSON в `owasp_sessions/`.

Подробнее: [docs/OWASP_INTEGRATION.md](docs/OWASP_INTEGRATION.md).

---

## Меню после проверки IP

После пункта **1** (интерактивно, TTY):

| № | Инструмент |
|---|------------|
| 1 | `nmap -A -T4` (Ctrl+C / Ctrl+Z — стоп, возврат в меню) |
| 2 | `traceroute`/`tracert` до 8.8.8.8 (≤20 хопов) |
| 3 | `nslookup` проверяемого IP |
| 4 | OWASP Secure Headers (быстро) |
| 0 | Пропустить |

**Пример (nmap):**

```text
Running: nmap -A -T4 8.8.8.8
… (вывод nmap) …
— done —
Select (0-4):
```

> **Authorized use:** nmap, DNS wordlist, Amass, Nettacker — только для целей, на которые у вас есть разрешение.

---

## CLI (все режимы)

Полный список: `python3 fnkit.py -h`.

**Правило:** в одном процессе не смешиваются тяжёлые режимы — например `-i` и `--trace-monitor` в одной команде: сначала гео, потом отдельно диагностика.

### Проверка зависимостей

```bash
python3 fnkit.py --check-deps
python3 fnkit.py --check-deps --check-deps-group dns --check-deps-hints
```

### GitHub Actions

Workflow **Manual Run** (`.github/workflows/manual-run.yml`):

| Input | Описание |
|-------|----------|
| `ip` | Один IP (`--ip`) |
| `asn` | ASN (`--asn`) |
| `range_start` + `range_end` | Диапазон (`--range`) |
| `save` | `true` → `--save` |
| `auto_reclass` | `--auto-reclass` |
| `quiet` | `--quiet` (только с `auto_reclass=true`) |
| `max_ips` | `--max-ips N` |

Артефакт: `scan_results.json` при `save=true`.

### PowerShell — сводка команд

| Команда | Назначение |
|---------|------------|
| `.\fnkit.ps1 -i 8.8.8.8` | Проверка одного IP |
| `.\fnkit.ps1 -r 10.0.0.1 10.0.0.20 --max-ips 10` | Диапазон |
| `.\fnkit.ps1 -a AS12389 -s` | ASN + сохранение |
| `.\fnkit.ps1 --speed-test` | Speed-test |
| `.\fnkit.ps1 --dns example.com --dns-save` | DNS crawl |

---

## Справочник CLI — все флаги

| Флаг | Группа | Описание |
|------|--------|----------|
| `-h` | — | Справка |
| `-i`, `--ip` | Geo | Один IP |
| `-r START END`, `--range` | Geo | Диапазон |
| `-a`, `--asn` | Geo | ASN |
| `-s`, `--save` | Geo | `scan_results.json` |
| `--max-ips` | Geo | Лимит IP в диапазоне (default 256) |
| `--auto-reclass` | Geo | Авто-переклассификация |
| `--quiet` | Geo | С `--auto-reclass` |
| `--speed-test` | Diag | ICMP + Cloudflare HTTP |
| `--trace-monitor HOST` | Diag | Монитор маршрута |
| `--trace-interval SEC` | Diag | Интервал ping (default 3) |
| `--trace-max-hops N` | Diag | Хопы traceroute (default 30) |
| `--trace-rediscover N` | Diag | Повтор traceroute (default 45) |
| `--trace-replay FILE` | Diag | Воспроизведение JSON |
| `--trace-replay-delay SEC` | Diag | Пауза между раундами (default 0.25) |
| `--pcap-show FILE` | PCAP | Просмотр файла |
| `--pcap-max-packets N` | PCAP | Лимит кадров (default 80) |
| `--pcap-hex` | PCAP | Hex-дамп (tshark) |
| `--pcap-capture IFACE` | PCAP | Захват (нужен `--pcap-out`) |
| `--pcap-out FILE` | PCAP | Путь записи |
| `--pcap-seconds SEC` | PCAP | Длительность (default 10) |
| `--pcap-filter BPF` | PCAP | Фильтр tcpdump |
| `--dns DOMAIN` | DNS | Crawl |
| `--dns-depth` | DNS | Глубина BFS (default 4) |
| `--dns-max-domains` | DNS | Лимит доменов (default 500) |
| `--dns-save` | DNS | Сохранить сессию |
| `--dns-wordlist FILE` | DNS | Поддомены |
| `--dns-crtsh` | DNS | crt.sh |
| `--dns-qps` | DNS | Rate limit (default 20) |
| `--dns-replay FILE` | DNS | Сводка сессии |
| `--dns-export FILE` | DNS | HTML-граф |
| `--dns-pcap FILE` | DNS | Seed из PCAP |
| `--owasp-headers URL` | OWASP | Secure Headers |
| `--owasp-amass DOMAIN` | OWASP | Amass passive |
| `--owasp-nettacker HOST` | OWASP | Nettacker scan |
| `--owasp-wstg` | OWASP | Чеклист WSTG |
| `--owasp-pipeline` | OWASP | Сценарий pipeline |
| `--owasp-ip` | OWASP | IP для pipeline |
| `--owasp-domain` | OWASP | Домен для pipeline/Amass |
| `--owasp-nettacker-run` | OWASP | Nettacker в pipeline |
| `--owasp-save` | OWASP | `owasp_sessions/` |
| `--check-deps` | Meta | Проверка зависимостей |
| `--check-deps-group` | Meta | minimal, dns, pcap, owasp, full… |
| `--check-deps-hints` | Meta | Подсказки установки |

---

## Форматы JSON-файлов

### `scan_results.json` (флаг `-s` / сохранение отчёта)

```json
{
  "timestamp": "2026-05-19T12:00:00",
  "results": [
    {
      "ip": "8.8.8.8",
      "matches": [{ "asn": "AS15169", "expected_country": "US", "pool": "8.0.0.0/8" }],
      "mismatches": [],
      "geo_data": { "country_code": "US", "country": "United States" }
    }
  ],
  "mismatches_found": 0
}
```

### `trace_sessions/*.json`

```json
{
  "format": "fnkit_trace_v1",
  "target": "8.8.8.8",
  "capture_iface": "en0",
  "rounds": [ { "round": 1, "hops": [ { "hop": 1, "ip": "192.168.1.1", "rtt_ms": 1.2 } ] } ]
}
```

Legacy: `"format": "ip_checker_trace_v1"` — тоже читается.

### `dns_sessions/*.json`

```json
{
  "format": "fnkit_dns_v1",
  "seed": "example.com",
  "nodes": [ { "id": "example.com", "type": "domain", "depth": 0 } ],
  "edges": [ { "from": "example.com", "to": "93.184.216.34", "rtype": "A" } ]
}
```

### `owasp_sessions/*.json`

```json
{
  "format": "fnkit_owasp_v1",
  "created_at": "2026-05-19T12:00:00+00:00",
  "steps": [ { "name": "secure_headers", "url": "https://example.com/", "ok": true } ]
}
```

### `asn_database.json` (фрагмент)

```json
{
  "metadata": {
    "last_updated": "2026-05-19",
    "quarantine_cases": [
      {
        "ip": "1.2.3.4",
        "expected_country": "RU",
        "ip_api_country": "DE",
        "whois_country": "NL",
        "status": "open"
      }
    ]
  },
  "asn_data": [
    {
      "asn": "AS12389",
      "owner": "Example ISP",
      "expected_country": "GB",
      "ip_pools": ["83.0.0.0/8"]
    }
  ]
}
```

---

## Политика источников и карантин

При mismatch страны:

- Считается **confidence score** (ip-api, WHOIS, согласованность, RIR)  
- Высокий score + согласие whois и ip-api → возможна **авто-переклассификация** (`--auto-reclass`)  
- **Конфликт** whois ≠ ip-api → кейс в `metadata.quarantine_cases`, **без** авто-записи в БД  
- Слабые сигналы → сохраняется текущий `expected_country`

Поля карантина: timestamp, ip, asn, pool, страны, reason, `status: open`.

---

## Устранение неполадок

| Проблема | Что проверить |
|----------|----------------|
| WHOIS не работает | `whois 8.8.8.8`, интернет, таймаут 20 с в UI |
| IP не в базе | Flow unknown IP или правка `asn_database.json` |
| `--quiet` молчит не так | Только с `--auto-reclass` |
| Нет `p`/`q` в trace | Нужен TTY |
| PCAP пустой | `sudo`, верный интерфейс (меню **5**) |
| DNS меню недоступно | `pip install dnspython` |
| Amass/Nettacker | `python3 fnkit.py --check-deps-group owasp --check-deps-hints` |
| nmap не прерывается | macOS/Linux: Ctrl+C или Ctrl+Z |

---

## SBOM и CI

- SBOM: `sbom.cdx.json` (CycloneDX 1.5), `sbom.spdx.json` (SPDX 2.3)  
- Версия приложения в манифесте: **0.2.0**  
- Регенерация: `python3 tools/generate_sbom.py`  
- CI проверяет синтаксис, `fnkit.py -h`, актуальность SBOM (Python 3.10)

---

## Сообщество

- [Contributing](CONTRIBUTING.md)  
- [Code of Conduct](CODE_OF_CONDUCT.md)  
- [Security policy](.github/SECURITY.md)

---

## Лицензия

MIT — см. [LICENSE](LICENSE).
