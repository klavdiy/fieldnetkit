#!/usr/bin/env python3
"""
IP pivot map — graph centered on a seed IP (passive DNS → domains → peer IPs).

Depth (resolve hops from seed):
  0 — passive only: PTR, historical hostnames, BGP/ASN on the seed IP (no forward DNS).
  1 — one hop: resolve hostnames on the seed to A/AAAA (co-hosted / linked IPs).
  2 — two hops: passive DNS on those peer IPs + resolve their hostnames to further IPs.
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import pdns_lookup

from paths import PIVOT_GRAPH_DIR, PIVOT_SESSIONS_DIR
from schema import DocumentKind, FORMAT_PIVOT_V1, load_json_file, save_json_file

try:
    import dns.resolver

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

PIVOT_FORMAT_V1 = FORMAT_PIVOT_V1

STRINGS: Dict[str, Dict[str, str]] = {
    "en": {
        "title": "IP pivot map",
        "building": "Building IP pivot graph (depth {depth})…",
        "need_dns": "dnspython required for depth ≥ 1: pip install -r requirements-dns.txt",
        "summary": "Pivot map: {nodes} nodes, {edges} edges, depth {depth}",
        "html_ok": "Pivot HTML: {path}",
        "session_ok": "Pivot session: {path}",
        "depth0_hint": "Depth 0: passive DNS / routing on seed only",
        "depth1_hint": "Depth 1: + resolve hostnames → linked IPs",
        "depth2_hint": "Depth 2: + passive DNS on linked IPs → next wave",
    },
    "ru": {
        "title": "IP pivot map",
        "building": "Построение IP pivot-графа (глубина {depth})…",
        "need_dns": "Для глубины ≥ 1 нужен dnspython: pip install -r requirements-dns.txt",
        "summary": "Pivot map: {nodes} узлов, {edges} рёбер, глубина {depth}",
        "html_ok": "Pivot HTML: {path}",
        "session_ok": "Pivot session: {path}",
        "depth0_hint": "Глубина 0: только passive DNS / routing на seed IP",
        "depth1_hint": "Глубина 1: + resolve hostname → связанные IP",
        "depth2_hint": "Глубина 2: + passive DNS на связанных IP → следующая волна",
    },
}


def msg(lang: str, key: str, **kwargs: Any) -> str:
    table = STRINGS.get(lang if lang in STRINGS else "en", STRINGS["en"])
    return table.get(key, key).format(**kwargs)


def normalize_domain(name: str) -> Optional[str]:
    n = (name or "").strip().lower().rstrip(".")
    if not n or "." not in n or " " in n:
        return None
    if n.endswith(".arpa"):
        return None
    return n


def _ip_id(ip: str) -> str:
    return f"ip:{ip}"


def _dom_id(domain: str) -> str:
    return f"dom:{domain}"


def _asn_id(asn: str) -> str:
    key = re.sub(r"[^A-Za-z0-9]", "", (asn or "").upper())
    return f"asn:{key or 'unknown'}"


class PivotGraph:
    def __init__(self, seed_ip: str) -> None:
        self.seed_ip = seed_ip
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self._edge_keys: Set[Tuple[str, str, str]] = set()

    def add_node(self, nid: str, ntype: str, label: str, **meta: Any) -> None:
        if nid not in self.nodes:
            self.nodes[nid] = {"id": nid, "type": ntype, "label": label, **meta}
        else:
            self.nodes[nid].update({k: v for k, v in meta.items() if v is not None})

    def add_edge(self, src: str, dst: str, rtype: str, **extra: Any) -> None:
        key = (src, dst, rtype)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        e: Dict[str, Any] = {"from": src, "to": dst, "rtype": rtype}
        e.update(extra)
        self.edges.append(e)

    def to_session(
        self,
        *,
        depth: int,
        stats: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "format": PIVOT_FORMAT_V1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "seed_ip": self.seed_ip,
            "depth": depth,
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "stats": stats or {},
        }


def resolve_domain_ips(domain: str, *, timeout: float = 5.0) -> List[str]:
    """Forward A/AAAA for a hostname."""
    if not HAS_DNSPYTHON:
        return []
    dom = normalize_domain(domain)
    if not dom:
        return []
    res = dns.resolver.Resolver()
    res.lifetime = timeout
    ips: List[str] = []
    for rtype in ("A", "AAAA"):
        try:
            ans = res.resolve(dom, rtype)
            for rr in ans:
                ip = str(rr).strip()
                try:
                    ipaddress.ip_address(ip)
                    ips.append(ip)
                except ValueError:
                    continue
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
        ):
            continue
    return list(dict.fromkeys(ips))


def _hostnames_from_pdns(report: Dict[str, Any]) -> List[str]:
    hosts: List[str] = []
    for key in ("ptr_names", "forward_names"):
        for h in report.get(key) or []:
            d = normalize_domain(str(h))
            if d:
                hosts.append(d)
    for row in report.get("resolutions") or []:
        d = normalize_domain(str(row.get("hostname", "")))
        if d:
            hosts.append(d)
    return list(dict.fromkeys(hosts))


def _attach_pdns_to_graph(graph: PivotGraph, ip: str, report: Dict[str, Any]) -> None:
    iid = _ip_id(ip)
    graph.add_node(iid, "ip", ip, hop=report.get("_hop", 0), seed=(ip == graph.seed_ip))

    for ptr in report.get("ptr_names") or []:
        d = normalize_domain(str(ptr))
        if d:
            did = _dom_id(d)
            graph.add_node(did, "domain", d, role="ptr")
            graph.add_edge(iid, did, "PTR", source="ripe")

    for row in report.get("resolutions") or []:
        host = normalize_domain(str(row.get("hostname", "")))
        if not host:
            continue
        did = _dom_id(host)
        graph.add_node(
            did,
            "domain",
            host,
            last_seen=row.get("last_seen"),
            source=row.get("source"),
        )
        graph.add_edge(
            iid,
            did,
            "pdns",
            source=row.get("source", "?"),
            last_seen=row.get("last_seen"),
        )

    for fwd in report.get("forward_names") or []:
        d = normalize_domain(str(fwd))
        if d:
            did = _dom_id(d)
            graph.add_node(did, "domain", d, role="forward")
            graph.add_edge(iid, did, "forward", source="ripe")

    seen_asn: Set[str] = set()
    for row in report.get("routing_origins") or []:
        asn = (row.get("asn") or "").strip()
        if not asn or asn in seen_asn:
            continue
        seen_asn.add(asn)
        aid = _asn_id(asn)
        graph.add_node(aid, "asn", asn, prefix=row.get("prefix"))
        graph.add_edge(iid, aid, "origin", prefix=row.get("prefix"), source="ripe-routing")


def build_pivot_map(
    seed_ip: str,
    *,
    depth: int = 1,
    pdns_report: Optional[Dict[str, Any]] = None,
    geo_context: Optional[Dict[str, Any]] = None,
    virustotal_api_key: Optional[str] = None,
    securitytrails_api_key: Optional[str] = None,
    max_domains_per_ip: int = 40,
    max_ips_total: int = 80,
    qps: float = 8.0,
    lang: str = "en",
    print_fn: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
  Build pivot graph. ``depth`` 0|1|2 — see module docstring.
    """
    out = print_fn or (lambda s: None)
    depth = max(0, min(2, int(depth)))
    if depth >= 1 and not HAS_DNSPYTHON:
        return {"success": False, "error": msg(lang, "need_dns"), "depth": depth}

    try:
        ipaddress.ip_address(seed_ip)
    except ValueError:
        return {"success": False, "error": "invalid IP", "depth": depth}

    out(msg(lang, "building", depth=depth))
    graph = PivotGraph(seed_ip)
    pdns_cache: Dict[str, Dict[str, Any]] = {}
    visited_ips: Set[str] = set()
    queued_ips: Set[str] = {seed_ip}
    queue: List[Tuple[str, int]] = [(seed_ip, 0)]
    stats = {"ips_processed": 0, "domains_resolved": 0, "truncated": False}
    delay = 1.0 / max(qps, 0.5)

    if geo_context:
        iid = _ip_id(seed_ip)
        graph.add_node(
            iid,
            "ip",
            seed_ip,
            hop=0,
            seed=True,
            country=geo_context.get("country_code"),
            asn=geo_context.get("asn"),
            isp=geo_context.get("isp"),
        )

    while queue and len(visited_ips) < max_ips_total:
        ip, hop = queue.pop(0)
        if ip in visited_ips:
            continue
        visited_ips.add(ip)
        stats["ips_processed"] += 1

        if ip == seed_ip and pdns_report and pdns_report.get("success"):
            report = dict(pdns_report)
        elif ip in pdns_cache:
            report = pdns_cache[ip]
        else:
            report = pdns_lookup.lookup_passive_dns(
                ip,
                virustotal_api_key=virustotal_api_key,
                securitytrails_api_key=securitytrails_api_key,
                lang=lang if lang in ("en", "ru") else "en",
            )
            pdns_cache[ip] = report

        report["_hop"] = hop
        if report.get("success"):
            _attach_pdns_to_graph(graph, ip, report)
        elif ip == seed_ip and geo_context:
            pass
        elif ip not in graph.nodes:
            graph.add_node(_ip_id(ip), "ip", ip, hop=hop)

        if depth > hop and report.get("success"):
            hosts = _hostnames_from_pdns(report)[:max_domains_per_ip]
            for host in hosts:
                if len(visited_ips) >= max_ips_total:
                    stats["truncated"] = True
                    break
                stats["domains_resolved"] += 1
                time.sleep(delay)
                for peer_ip in resolve_domain_ips(host):
                    if peer_ip == ip:
                        continue
                    did = _dom_id(host)
                    graph.add_node(did, "domain", host)
                    pid = _ip_id(peer_ip)
                    graph.add_node(pid, "ip", peer_ip, hop=hop + 1)
                    graph.add_edge(did, pid, "A/AAAA")
                    next_hop = hop + 1
                    if peer_ip not in visited_ips and peer_ip not in queued_ips and next_hop < depth:
                        if len(visited_ips) + len(queued_ips) < max_ips_total:
                            queue.append((peer_ip, next_hop))
                            queued_ips.add(peer_ip)
                        else:
                            stats["truncated"] = True

    session = graph.to_session(depth=depth, stats=stats)
    session["success"] = True
    return session


def export_pivot_html(
    session: Dict[str, Any],
    out_path: Optional[Path] = None,
    *,
    lang: str = "en",
) -> Path:
    PIVOT_GRAPH_DIR.mkdir(parents=True, exist_ok=True)
    seed = str(session.get("seed_ip", "pivot"))
    safe = re.sub(r"[^a-z0-9.-]+", "_", seed)[:60]
    path = out_path or (PIVOT_GRAPH_DIR / f"pivot_{safe}.html")
    nodes_json = json.dumps(session.get("nodes", []), ensure_ascii=False)
    edges_json = json.dumps(session.get("edges", []), ensure_ascii=False)
    title = escape(seed)
    depth = session.get("depth", "?")
    nc = len(session.get("nodes", []))
    ec = len(session.get("edges", []))
    path.write_text(
        f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>IP pivot — {title}</title>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 0; }}
    #header {{ padding: 12px 16px; background: #16213e; color: #eee; }}
    #mynetwork {{ width: 100%; height: calc(100vh - 56px); }}
  </style>
</head>
<body>
  <div id="header"><strong>IP pivot map</strong> — {title}
    <span style="opacity:.7"> · depth {depth} · {nc} nodes · {ec} edges</span>
  </div>
  <div id="mynetwork"></div>
  <script>
    const color = (n) => {{
      if (n.type === 'ip') return n.seed ? '#e94560' : '#4ecdc4';
      if (n.type === 'asn') return '#f5a623';
      return '#95e1d3';
    }};
    const shape = (n) => (n.type === 'ip' ? 'box' : (n.type === 'asn' ? 'diamond' : 'dot'));
    const nodes = new vis.DataSet({nodes_json}.map(n => ({{
      id: n.id,
      label: (n.label || n.id).slice(0, 42),
      title: JSON.stringify(n, null, 1),
      color: color(n),
      shape: shape(n),
    }})));
    const edges = new vis.DataSet({edges_json}.map((e, i) => ({{
      id: i, from: e.from, to: e.to, label: e.rtype, arrows: 'to', font: {{ size: 10 }},
    }})));
    new vis.Network(document.getElementById('mynetwork'), {{ nodes, edges }},
      {{ physics: {{ stabilization: true }}, edges: {{ smooth: true }} }});
  </script>
</body>
</html>""",
        encoding="utf-8",
    )
    return path


def save_pivot_session(session: Dict[str, Any], path: Optional[Path] = None) -> Path:
    PIVOT_SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    seed = str(session.get("seed_ip", "x"))
    safe = re.sub(r"[^a-z0-9.-]+", "_", seed)[:40]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = path or (PIVOT_SESSIONS_DIR / f"pivot_{safe}_{stamp}.json")
    save_json_file(out, DocumentKind.PIVOT_SESSION, session)
    return out


def load_pivot_session(path: Path) -> Dict[str, Any]:
    return load_json_file(path, DocumentKind.PIVOT_SESSION)


def print_pivot_summary(session: Dict[str, Any], *, lang: str = "en") -> None:
    if not session.get("success"):
        print(msg(lang, "need_dns") if "dnspython" in str(session.get("error", "")) else session.get("error"))
        return
    depth = session.get("depth", 0)
    print(
        msg(
            lang,
            "summary",
            nodes=len(session.get("nodes", [])),
            edges=len(session.get("edges", [])),
            depth=depth,
        )
    )
    print(f"  {msg(lang, 'depth0_hint')}")
    if depth >= 1:
        print(f"  {msg(lang, 'depth1_hint')}")
    if depth >= 2:
        print(f"  {msg(lang, 'depth2_hint')}")
