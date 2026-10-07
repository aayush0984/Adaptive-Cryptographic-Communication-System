"""Phase 10 — Network Traffic Analysis module using PyShark.

Analyzes Phase 9 .pcapng files generated during IoT cryptographic experiments
to measure network performance, transmission directionality, TCP protocol behavior,
and communication overhead.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from zoneinfo import ZoneInfo

import pyshark

from config import get_env

# Indian Standard Time (IST = UTC+05:30)
IST = ZoneInfo("Asia/Kolkata")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TrafficAnalysisError(Exception):
    """Raised when traffic analysis encounters an unrecoverable condition."""


class TrafficAnalyzer:
    """Extracts network metrics and calculates transmission overhead using PyShark."""

    def __init__(
        self,
        db: Any = None,
        project_root: Optional[Path] = None,
        server_port: Optional[int] = None,
    ) -> None:
        self._db = db
        self.project_root = project_root or _PROJECT_ROOT
        self.default_server_port = (
            server_port
            if server_port is not None
            else int(get_env("SERVER_PORT", "5000") or "5000")
        )

    @property
    def db(self) -> Any:
        if self._db is None:
            from database.connection import get_database

            self._db = get_database()
        return self._db

    def _resolve_server_port(self, capture_doc: Optional[dict[str, Any]] = None) -> int:
        """Determine server port from capture doc filter or configuration."""
        if capture_doc and capture_doc.get("capture_filter"):
            match = re.search(r"port\s+(\d+)", capture_doc["capture_filter"], re.IGNORECASE)
            if match:
                return int(match.group(1))
        return self.default_server_port

    def _resolve_message_size(
        self,
        experiment_id: str,
        capture_doc: Optional[dict[str, Any]] = None,
        pcap_path: Optional[Path] = None,
    ) -> Optional[int]:
        """Obtain original message size in bytes from capture doc, experiment, or filename."""
        # 1. From capture_doc root if already stored
        if capture_doc and capture_doc.get("message_size_bytes") is not None:
            return int(capture_doc["message_size_bytes"])

        # 2. From experiments collection
        try:
            exp_doc = self.db["experiments"].find_one({"experiment_id": experiment_id})
            if exp_doc:
                obs = exp_doc.get("observed_results", {})
                if obs and obs.get("message_size_bytes") is not None:
                    return int(obs["message_size_bytes"])
                if exp_doc.get("message_size_bytes") is not None:
                    return int(exp_doc["message_size_bytes"])
        except Exception:
            pass

        # 3. From capture filename pattern (e.g. experiment_<id>_<profile>_<size>B.pcapng)
        path_str = str(pcap_path) if pcap_path else ""
        if not path_str and capture_doc and capture_doc.get("capture_file"):
            path_str = str(capture_doc["capture_file"])

        if path_str:
            match = re.search(r"_(\d+)B\.pcapng$", path_str, re.IGNORECASE)
            if match:
                return int(match.group(1))

        return None

    def analyze_pcap(
        self,
        pcap_path: Path | str,
        original_message_size_bytes: Optional[int] = None,
        server_port: Optional[int] = None,
    ) -> dict[str, Any]:
        """Analyze a .pcapng file and return a comprehensive metrics dictionary.

        Does not store plaintext or cryptographic secrets.
        """
        path = Path(pcap_path).resolve()
        port = server_port if server_port is not None else self.default_server_port

        # ── Error check 1: File existence ────────────────────────────────────
        if not path.exists():
            return {
                "analysis_status": "failed",
                "analysis_error": f"Capture file not found: {path}",
                "analyzed_at": datetime.now(IST),
            }

        # ── Error check 2: File size ─────────────────────────────────────────
        file_bytes = path.stat().st_size
        if file_bytes == 0:
            return {
                "analysis_status": "failed",
                "analysis_error": f"Capture file is empty (0 bytes): {path.name}",
                "analyzed_at": datetime.now(IST),
            }

        # ── Error check 3: Message size for overhead ─────────────────────────
        if original_message_size_bytes is None:
            return {
                "analysis_status": "failed",
                "analysis_error": "Missing original message size information for network overhead calculation",
                "analyzed_at": datetime.now(IST),
            }

        total_packets = 0
        tcp_packets = 0
        s2r_packets = 0
        r2s_packets = 0
        s2r_bytes = 0
        r2s_bytes = 0
        tcp_payload_bytes = 0
        tcp_retransmissions = 0
        app_data_packets = 0
        min_size: Optional[int] = None
        max_size: Optional[int] = None
        first_packet_at: Optional[datetime] = None
        last_packet_at: Optional[datetime] = None
        protocols_seen_set: set[str] = set()

        cap = None
        try:
            # Open pcap with keep_packets=False to prevent unbounded RAM usage
            cap = pyshark.FileCapture(str(path), keep_packets=False)

            for pkt in cap:
                total_packets += 1
                pkt_len = int(pkt.length)

                if min_size is None or pkt_len < min_size:
                    min_size = pkt_len
                if max_size is None or pkt_len > max_size:
                    max_size = pkt_len

                # Sniff timestamp
                t = pkt.sniff_time
                if t.tzinfo is None:
                    t = t.replace(tzinfo=IST)
                else:
                    t = t.astimezone(IST)

                if first_packet_at is None:
                    first_packet_at = t
                last_packet_at = t

                # Protocols seen (normalize layer names)
                for layer in pkt.layers:
                    l_name = layer.layer_name.lower()
                    if not l_name.startswith("_"):
                        if l_name in ("null", "loopback", "eth", "ethernet"):
                            protocols_seen_set.add("ETH")
                        elif l_name == "ip":
                            protocols_seen_set.add("IP")
                        elif l_name == "ipv6":
                            protocols_seen_set.add("IPV6")
                        elif l_name == "tcp":
                            protocols_seen_set.add("TCP")

                # TCP layer analysis
                if "tcp" in pkt or hasattr(pkt, "tcp"):
                    tcp_packets += 1
                    tcp = pkt.tcp

                    dst_p = int(tcp.dstport)
                    src_p = int(tcp.srcport)

                    p_payload_len = int(getattr(tcp, "len", 0))
                    tcp_payload_bytes += p_payload_len
                    if p_payload_len > 0:
                        app_data_packets += 1

                    if (
                        hasattr(tcp, "analysis_retransmission")
                        or hasattr(tcp, "analysis_fast_retransmission")
                        or hasattr(tcp, "analysis_spurious_retransmission")
                    ):
                        tcp_retransmissions += 1

                    # Direction determination based on server port
                    if dst_p == port:
                        s2r_packets += 1
                        s2r_bytes += pkt_len
                    elif src_p == port:
                        r2s_packets += 1
                        r2s_bytes += pkt_len

        except Exception as exc:
            return {
                "analysis_status": "failed",
                "analysis_error": f"PyShark capture parsing error: {exc}",
                "analyzed_at": datetime.now(IST),
            }
        finally:
            if cap is not None:
                try:
                    cap.close()
                except Exception:
                    pass

        # ── Error check 4: No matching TCP traffic ───────────────────────────
        if tcp_packets == 0:
            return {
                "analysis_status": "failed",
                "analysis_error": f"Capture contains no matching TCP traffic on port {port}",
                "analyzed_at": datetime.now(IST),
            }

        # ── Overhead & averages calculation ──────────────────────────────────
        total_captured_bytes = file_bytes
        avg_packet_size = (
            round(total_captured_bytes / total_packets, 2)
            if total_packets > 0
            else 0.0
        )

        network_overhead_bytes = total_captured_bytes - original_message_size_bytes
        network_overhead_percent = (
            round((network_overhead_bytes / original_message_size_bytes) * 100, 2)
            if original_message_size_bytes > 0
            else 0.0
        )

        traffic_duration = (
            round((last_packet_at - first_packet_at).total_seconds(), 3)
            if first_packet_at and last_packet_at
            else 0.0
        )

        # Canonical ordering for protocols
        proto_hierarchy = ["ETH", "IP", "IPV6", "TCP"]
        protocols_seen = [p for p in proto_hierarchy if p in protocols_seen_set]
        # Include any other upper protocols
        for p in sorted(protocols_seen_set):
            if p not in protocols_seen:
                protocols_seen.append(p)

        return {
            "analysis_status": "completed",
            "message_size_bytes": original_message_size_bytes,
            "total_packets": total_packets,
            "tcp_packets": tcp_packets,
            "total_captured_bytes": total_captured_bytes,
            "min_packet_size_bytes": min_size or 0,
            "max_packet_size_bytes": max_size or 0,
            "average_packet_size_bytes": avg_packet_size,
            "sender_to_receiver_packets": s2r_packets,
            "receiver_to_sender_packets": r2s_packets,
            "sender_to_receiver_bytes": s2r_bytes,
            "receiver_to_sender_bytes": r2s_bytes,
            "tcp_payload_bytes": tcp_payload_bytes,
            "tcp_retransmissions": tcp_retransmissions,
            "application_data_packets": app_data_packets,
            "network_overhead_bytes": network_overhead_bytes,
            "network_overhead_percent": network_overhead_percent,
            "protocols_seen": protocols_seen,
            "first_packet_at": first_packet_at,
            "last_packet_at": last_packet_at,
            "traffic_duration_seconds": traffic_duration,
            "analyzed_at": datetime.now(IST),
            "analysis_error": None,
        }

    def analyze_experiment(
        self,
        experiment_id: str,
        persist: bool = True,
    ) -> dict[str, Any]:
        """Analyze the capture associated with experiment_id and optionally update MongoDB.

        Idempotent: Re-running updates existing document without destroying Phase 9 data.
        """
        capture_doc = self.db["traffic"].find_one({"experiment_id": experiment_id})
        if not capture_doc:
            # Check if file exists under captures/
            potential_file = list(self.project_root.glob(f"captures/*{experiment_id}*.pcapng"))
            if not potential_file:
                err_dict = {
                    "analysis_status": "failed",
                    "analysis_error": f"No traffic capture document found in MongoDB for experiment '{experiment_id}'",
                    "analyzed_at": datetime.now(IST),
                }
                return err_dict

            pcap_path = potential_file[0]
            capture_file_rel = str(pcap_path.relative_to(self.project_root))
            capture_doc = {
                "experiment_id": experiment_id,
                "capture_file": capture_file_rel,
            }
        else:
            rel_or_abs = capture_doc.get("capture_file", "")
            pcap_path = Path(rel_or_abs)
            if not pcap_path.is_absolute():
                pcap_path = (self.project_root / pcap_path).resolve()

        server_port = self._resolve_server_port(capture_doc)
        msg_size = self._resolve_message_size(experiment_id, capture_doc, pcap_path)

        analysis = self.analyze_pcap(
            pcap_path=pcap_path,
            original_message_size_bytes=msg_size,
            server_port=server_port,
        )

        if persist:
            update_set: dict[str, Any] = {"traffic_analysis": analysis}
            if msg_size is not None and capture_doc.get("message_size_bytes") is None:
                update_set["message_size_bytes"] = msg_size

            self.db["traffic"].update_one(
                {"experiment_id": experiment_id},
                {"$set": update_set},
                upsert=True,
            )

            # Keep reference updated in experiments collection if it exists
            try:
                self.db["experiments"].update_one(
                    {"experiment_id": experiment_id},
                    {
                        "$set": {
                            "packet_capture.analysis_status": analysis.get("analysis_status"),
                        }
                    },
                    upsert=False,
                )
            except Exception:
                pass

        return analysis

    def analyze_pending(self, persist: bool = True) -> list[dict[str, Any]]:
        """Find all traffic captures not yet analyzed (or failed) and analyze them."""
        query = {
            "$or": [
                {"traffic_analysis": {"$exists": False}},
                {"traffic_analysis.analysis_status": {"$ne": "completed"}},
            ]
        }
        cursor = self.db["traffic"].find(query)
        results = []
        for doc in cursor:
            exp_id = doc.get("experiment_id")
            if exp_id:
                res = self.analyze_experiment(exp_id, persist=persist)
                results.append({"experiment_id": exp_id, "analysis": res})
        return results

    def analyze_all(self, persist: bool = True) -> list[dict[str, Any]]:
        """Analyze all captures in the traffic collection."""
        cursor = self.db["traffic"].find({})
        results = []
        for doc in cursor:
            exp_id = doc.get("experiment_id")
            if exp_id:
                res = self.analyze_experiment(exp_id, persist=persist)
                results.append({"experiment_id": exp_id, "analysis": res})
        return results

    @staticmethod
    def format_summary(experiment_id: str, analysis: dict[str, Any]) -> str:
        """Format a concise terminal summary matching Phase 10 specifications."""
        status = analysis.get("analysis_status", "unknown")
        lines = [
            "============= TRAFFIC ANALYSIS =============",
            f"Experiment       : {experiment_id}",
        ]
        msg_size = analysis.get("message_size_bytes")
        if msg_size is None:
            msg_size = analysis.get("original_message_size_bytes")
        if msg_size is not None:
            lines.append(f"Message size     : {msg_size} B")

        if status == "completed":
            lines.extend(
                [
                    f"Packets          : {analysis.get('total_packets', 0)}",
                    f"Captured bytes   : {analysis.get('total_captured_bytes', 0)}",
                    f"TCP payload      : {analysis.get('tcp_payload_bytes', 0)} B",
                    f"Retransmissions  : {analysis.get('tcp_retransmissions', 0)}",
                    f"Network overhead : {analysis.get('network_overhead_bytes', 0)} B",
                    f"Overhead         : {analysis.get('network_overhead_percent', 0.0):.2f}%",
                    f"Status           : {status}",
                ]
            )
        else:
            lines.extend(
                [
                    f"Status           : {status}",
                    f"Error            : {analysis.get('analysis_error', 'Unknown error')}",
                ]
            )
        lines.append("============================================")
        return "\n".join(lines)


def analyze_capture(
    experiment_id: Optional[str] = None,
    pcap_path: Optional[Path | str] = None,
    persist: bool = True,
) -> dict[str, Any]:
    """Helper function to quickly analyze a capture by experiment ID or pcap path."""
    analyzer = TrafficAnalyzer()
    if experiment_id:
        return analyzer.analyze_experiment(experiment_id, persist=persist)
    elif pcap_path:
        return analyzer.analyze_pcap(pcap_path)
    else:
        raise ValueError("Must provide either experiment_id or pcap_path.")

