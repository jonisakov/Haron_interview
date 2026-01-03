#!/usr/bin/env python3
import re
import sys
import argparse
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

import pandas as pd

# Example expected line shape (with -tt -nn):
# 1704300000.123456 IP 10.0.0.5.51514 > 1.1.1.1.443: Flags [S], seq 123, win 64240, length 0
#
# Works well for IPv4 and most IPv6 tcpdump forms where port is appended as ".<port>".
LINE_RE = re.compile(
    r"^(?P<ts>\d+(?:\.\d+)?)\s+(?P<ipver>IP6?|IP)\s+(?P<src>\S+)\s+>\s+(?P<dst>[^:]+):\s+(?P<rest>.*)$"
)

FLAGS_RE = re.compile(r"\bFlags\s+\[(?P<flags>[^\]]+)\]")
LEN_RE = re.compile(r"\blength\s+(?P<len>\d+)\b", re.IGNORECASE)

# Best-effort “application protocol” detection from ports
PORT_TO_PROTO: Dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "smtp-submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    1883: "mqtt",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5672: "amqp",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
}

def split_host_port(addr: str) -> Tuple[str, Optional[int]]:
    """
    tcpdump with -nn prints host.port, where port is numeric.
    Split on the LAST '.' and accept if the suffix is digits.
    """
    if "." in addr:
        host, tail = addr.rsplit(".", 1)
        if tail.isdigit():
            return host, int(tail)
    return addr, None

def canonical_session_key(
    src_host: str, src_port: Optional[int],
    dst_host: str, dst_port: Optional[int],
) -> Tuple:
    """
    Bidirectional key: (TCP, ep1_host, ep1_port, ep2_host, ep2_port)
    """
    a = (src_host, src_port)
    b = (dst_host, dst_port)
    if a <= b:
        return ("TCP", src_host, src_port, dst_host, dst_port)
    return ("TCP", dst_host, dst_port, src_host, src_port)

def detect_app_proto(src_port: Optional[int], dst_port: Optional[int]) -> Optional[str]:
    """
    Best-effort: if either port matches a known service, return it.
    Prefer dst_port first (common client->server direction).
    """
    if dst_port is not None and dst_port in PORT_TO_PROTO:
        return PORT_TO_PROTO[dst_port]
    if src_port is not None and src_port in PORT_TO_PROTO:
        return PORT_TO_PROTO[src_port]
    return None

@dataclass
class SessionAgg:
    proto: str = "TCP"
    ep1_host: str = ""
    ep1_port: Optional[int] = None
    ep2_host: str = ""
    ep2_port: Optional[int] = None

    first_ts: float = 0.0
    last_ts: float = 0.0

    app_proto: Optional[str] = None

    packets_total: int = 0
    bytes_total: int = 0

    packets_fwd: int = 0
    packets_rev: int = 0
    bytes_fwd: int = 0
    bytes_rev: int = 0

    flags_counts: Dict[str, int] = field(default_factory=dict)

    def update(self, ts: float, length: int, is_fwd: bool, flags: Optional[str],
               src_port: Optional[int], dst_port: Optional[int]):
        if self.packets_total == 0:
            self.first_ts = ts
            self.last_ts = ts
        else:
            if ts < self.first_ts:
                self.first_ts = ts
            if ts > self.last_ts:
                self.last_ts = ts

        self.packets_total += 1
        self.bytes_total += length

        if is_fwd:
            self.packets_fwd += 1
            self.bytes_fwd += length
        else:
            self.packets_rev += 1
            self.bytes_rev += length

        if flags:
            self.flags_counts[flags] = self.flags_counts.get(flags, 0) + 1

        # Set app_proto once if we can infer it
        if self.app_proto is None:
            self.app_proto = detect_app_proto(src_port, dst_port)

def parse_tcpdump_line(line: str):
    m = LINE_RE.match(line.strip())
    if not m:
        return None

    ts = float(m.group("ts"))
    src_raw = m.group("src")
    dst_raw = m.group("dst")
    rest = m.group("rest")

    # Ensure it's TCP-ish: must have Flags [...]
    fm = FLAGS_RE.search(rest)
    if not fm:
        return None

    flags = fm.group("flags").strip()
    lm = LEN_RE.search(rest)
    length = int(lm.group("len")) if lm else 0

    src_host, src_port = split_host_port(src_raw)
    dst_host, dst_port = split_host_port(dst_raw)

    return {
        "ts": ts,
        "src_host": src_host,
        "src_port": src_port,
        "dst_host": dst_host,
        "dst_port": dst_port,
        "flags": flags,
        "length": length,
        "raw": line.rstrip("\n"),
    }

def tcpdump_log_to_sessions_df(lines) -> pd.DataFrame:
    sessions: Dict[Tuple, SessionAgg] = {}

    for line in lines:
        p = parse_tcpdump_line(line)
        if not p:
            continue

        key = canonical_session_key(p["src_host"], p["src_port"], p["dst_host"], p["dst_port"])
        _, ep1_host, ep1_port, ep2_host, ep2_port = key

        is_fwd = (
            p["src_host"] == ep1_host and p["src_port"] == ep1_port and
            p["dst_host"] == ep2_host and p["dst_port"] == ep2_port
        )

        if key not in sessions:
            sessions[key] = SessionAgg(
                ep1_host=ep1_host, ep1_port=ep1_port,
                ep2_host=ep2_host, ep2_port=ep2_port,
            )

        sessions[key].update(
            ts=p["ts"],
            length=p["length"],
            is_fwd=is_fwd,
            flags=p["flags"],
            src_port=p["src_port"],
            dst_port=p["dst_port"],
        )

    rows = []
    for s in sessions.values():
        rows.append({
            "proto": s.proto,
            "app_proto": s.app_proto,
            "ep1_host": s.ep1_host,
            "ep1_port": s.ep1_port,
            "ep2_host": s.ep2_host,
            "ep2_port": s.ep2_port,
            "first_ts": s.first_ts,
            "last_ts": s.last_ts,
            "duration_s": (s.last_ts - s.first_ts) if s.packets_total else 0.0,
            "packets_total": s.packets_total,
            "bytes_total": s.bytes_total,
            "packets_fwd": s.packets_fwd,
            "packets_rev": s.packets_rev,
            "bytes_fwd": s.bytes_fwd,
            "bytes_rev": s.bytes_rev,
            "tcp_flags_counts": dict(s.flags_counts),
        })

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values(["bytes_total", "packets_total"], ascending=False).reset_index(drop=True)
    return df

def main():
    ap = argparse.ArgumentParser(description="Parse tcpdump TCP log into a sessions DataFrame.")
    ap.add_argument("--file", help="Read tcpdump log from a file. If omitted, reads stdin.")
    ap.add_argument("--csv", help="Write output to CSV.")
    args = ap.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            df = tcpdump_log_to_sessions_df(f)
    else:
        df = tcpdump_log_to_sessions_df(sys.stdin)

    if df.empty:
        print("No TCP sessions parsed. Ensure tcpdump log was produced with -tt -nn and includes TCP Flags.", file=sys.stderr)
        sys.exit(1)

    # Preview
    with pd.option_context("display.max_rows", 50, "display.max_colwidth", 80):
        print(df.head(30).to_string(index=False))

    if args.csv:
        df.to_csv(args.csv, index=False)
        print(f"\nWrote: {args.csv}", file=sys.stderr)

if __name__ == "__main__":
    main()
