#!/usr/bin/env python3
"""Simple defensive IDS prototype.

Detects:
- DDoS-like request floods from a single source IP.
- Brute-force login attempts (many failed logins).
- Port scanning (many destination ports touched quickly).

Actions:
- Real-time console alerts.
- Automatic IP blocking (persisted in blocked_ips.txt).
- Lightweight dashboard rendered to dashboard.json and dashboard.html.

This tool is designed for lab/defensive monitoring scenarios.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Optional, Set, Tuple


@dataclass
class Alert:
    timestamp: str
    attack_type: str
    ip: str
    details: str
    blocked: bool


class IntrusionDetector:
    def __init__(
        self,
        ddos_threshold: int = 120,
        brute_threshold: int = 8,
        scan_threshold: int = 15,
        window_seconds: int = 60,
        blocklist_path: str = "blocked_ips.txt",
        dashboard_json_path: str = "dashboard.json",
        dashboard_html_path: str = "dashboard.html",
    ) -> None:
        self.ddos_threshold = ddos_threshold
        self.brute_threshold = brute_threshold
        self.scan_threshold = scan_threshold
        self.window_seconds = window_seconds

        self.blocklist_path = Path(blocklist_path)
        self.dashboard_json_path = Path(dashboard_json_path)
        self.dashboard_html_path = Path(dashboard_html_path)

        self.request_times: Dict[str, Deque[float]] = defaultdict(deque)
        self.failed_login_times: Dict[str, Deque[float]] = defaultdict(deque)
        self.port_targets: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)

        self.blocked_ips: Set[str] = self._load_blocked_ips()
        self.alerts: List[Alert] = []
        self.metrics = {
            "events_processed": 0,
            "blocked_ips_count": len(self.blocked_ips),
            "attack_counts": {
                "DDoS": 0,
                "Brute Force": 0,
                "Port Scanning": 0,
            },
        }

    def _load_blocked_ips(self) -> Set[str]:
        if not self.blocklist_path.exists():
            return set()
        return {
            line.strip()
            for line in self.blocklist_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }

    def _save_blocked_ips(self) -> None:
        self.blocklist_path.write_text(
            "\n".join(sorted(self.blocked_ips)) + ("\n" if self.blocked_ips else ""),
            encoding="utf-8",
        )

    def _cleanup_window(self, bucket: Deque[float], now_ts: float) -> None:
        cutoff = now_ts - self.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

    def _cleanup_ports(self, bucket: Deque[Tuple[float, int]], now_ts: float) -> None:
        cutoff = now_ts - self.window_seconds
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

    @staticmethod
    def _iso_now(ts: Optional[float] = None) -> str:
        dt = datetime.fromtimestamp(ts or time.time(), tz=timezone.utc)
        return dt.isoformat()

    def _raise_alert(self, attack_type: str, ip: str, details: str) -> None:
        already_blocked = ip in self.blocked_ips
        if not already_blocked:
            self.blocked_ips.add(ip)
            self._save_blocked_ips()

        self.metrics["blocked_ips_count"] = len(self.blocked_ips)
        self.metrics["attack_counts"][attack_type] += 1

        alert = Alert(
            timestamp=self._iso_now(),
            attack_type=attack_type,
            ip=ip,
            details=details,
            blocked=not already_blocked,
        )
        self.alerts.append(alert)

        block_status = "🔒 Blocked" if not already_blocked else "🔒 Already blocked"
        print(f"🚨 [{alert.timestamp}] {attack_type} from {ip} | {details} | {block_status}")

    def process_event(self, event: Dict[str, str]) -> None:
        ip = event.get("source_ip", "").strip()
        if not ip:
            return

        ts = float(event.get("timestamp", time.time()))
        event_type = event.get("event_type", "request").strip().lower()
        status = event.get("status", "").strip().lower()

        self.metrics["events_processed"] += 1

        # DDoS heuristic: too many requests from one IP inside window.
        req_bucket = self.request_times[ip]
        req_bucket.append(ts)
        self._cleanup_window(req_bucket, ts)
        if len(req_bucket) >= self.ddos_threshold:
            self._raise_alert(
                "DDoS",
                ip,
                f"{len(req_bucket)} requests within {self.window_seconds}s",
            )
            req_bucket.clear()

        # Brute-force heuristic: repeated failed login events.
        if event_type == "login" and status in {"failed", "deny", "denied"}:
            brute_bucket = self.failed_login_times[ip]
            brute_bucket.append(ts)
            self._cleanup_window(brute_bucket, ts)
            if len(brute_bucket) >= self.brute_threshold:
                self._raise_alert(
                    "Brute Force",
                    ip,
                    f"{len(brute_bucket)} failed logins within {self.window_seconds}s",
                )
                brute_bucket.clear()

        # Port-scan heuristic: many unique ports touched inside window.
        port_raw = event.get("dest_port", "")
        if port_raw:
            try:
                port = int(port_raw)
                scan_bucket = self.port_targets[ip]
                scan_bucket.append((ts, port))
                self._cleanup_ports(scan_bucket, ts)
                unique_ports = {p for _, p in scan_bucket}
                if len(unique_ports) >= self.scan_threshold:
                    self._raise_alert(
                        "Port Scanning",
                        ip,
                        f"Touched {len(unique_ports)} unique ports in {self.window_seconds}s",
                    )
                    scan_bucket.clear()
            except ValueError:
                pass

    def _dashboard_payload(self) -> Dict[str, object]:
        return {
            "generated_at": self._iso_now(),
            "metrics": self.metrics,
            "blocked_ips": sorted(self.blocked_ips),
            "alerts": [asdict(a) for a in self.alerts[-50:]],
        }

    def write_dashboard(self) -> None:
        payload = self._dashboard_payload()
        self.dashboard_json_path.write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        )

        html = f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <title>IDS Dashboard</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; background: #0f172a; color: #e2e8f0; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(220px, 1fr)); gap: 12px; margin-bottom: 20px; }}
    .card {{ background: #1e293b; padding: 12px; border-radius: 8px; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
    th, td {{ border-bottom: 1px solid #334155; padding: 8px; text-align: left; }}
  </style>
</head>
<body>
  <h1>📊 IDS Dashboard</h1>
  <p>Generated at: {payload['generated_at']}</p>
  <div class=\"grid\">
    <div class=\"card\"><strong>Events processed</strong><br>{self.metrics['events_processed']}</div>
    <div class=\"card\"><strong>Blocked IPs</strong><br>{self.metrics['blocked_ips_count']}</div>
    <div class=\"card\"><strong>DDoS alerts</strong><br>{self.metrics['attack_counts']['DDoS']}</div>
    <div class=\"card\"><strong>Brute-force alerts</strong><br>{self.metrics['attack_counts']['Brute Force']}</div>
    <div class=\"card\"><strong>Port-scan alerts</strong><br>{self.metrics['attack_counts']['Port Scanning']}</div>
  </div>

  <h2>🚨 Recent Alerts</h2>
  <table>
    <thead><tr><th>Time</th><th>Type</th><th>IP</th><th>Details</th><th>Blocked</th></tr></thead>
    <tbody>
      {''.join(f"<tr><td>{a['timestamp']}</td><td>{a['attack_type']}</td><td>{a['ip']}</td><td>{a['details']}</td><td>{'yes' if a['blocked'] else 'no'}</td></tr>" for a in payload['alerts'])}
    </tbody>
  </table>

  <h2>🔒 Blocked IPs</h2>
  <pre>{os.linesep.join(payload['blocked_ips']) if payload['blocked_ips'] else 'None'}</pre>
</body>
</html>
"""
        self.dashboard_html_path.write_text(html, encoding="utf-8")


def stream_csv(path: str) -> Iterable[Dict[str, str]]:
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield row


def main() -> int:
    parser = argparse.ArgumentParser(description="Defensive IDS prototype")
    parser.add_argument("--events-csv", required=True, help="Path to CSV file with events")
    parser.add_argument("--ddos-threshold", type=int, default=120)
    parser.add_argument("--brute-threshold", type=int, default=8)
    parser.add_argument("--scan-threshold", type=int, default=15)
    parser.add_argument("--window-seconds", type=int, default=60)
    args = parser.parse_args()

    detector = IntrusionDetector(
        ddos_threshold=args.ddos_threshold,
        brute_threshold=args.brute_threshold,
        scan_threshold=args.scan_threshold,
        window_seconds=args.window_seconds,
    )

    for event in stream_csv(args.events_csv):
        detector.process_event(event)

    detector.write_dashboard()
    print("\n✅ Dashboard written:")
    print(f"- {detector.dashboard_json_path}")
    print(f"- {detector.dashboard_html_path}")
    print(f"✅ Blocklist: {detector.blocklist_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
