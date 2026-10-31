"""Phase 10 — Network Traffic Analysis module using PyShark.

Analyzes Phase 9 .pcapng files generated during IoT cryptographic experiments
to measure network performance, transmission directionality, TCP protocol behavior,
and communication overhead.
"""

from __future__ import annotations

import re
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from zoneinfo import ZoneInfo

# PyShark compatibility shim for Python 3.12+ / 3.14 where child watchers were removed
class _DummyChildWatcher:
    def attach_loop(self, loop: Any) -> None:
        pass

if not hasattr(asyncio, "get_child_watcher"):
    asyncio.get_child_watcher = lambda: _DummyChildWatcher()  # type: ignore[attr-defined]
if not hasattr(asyncio, "set_child_watcher"):
    asyncio.set_child_watcher = lambda watcher: None  # type: ignore[attr-defined]
if not hasattr(asyncio, "SafeChildWatcher"):
    asyncio.SafeChildWatcher = _DummyChildWatcher  # type: ignore[attr-defined]

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
        total_frame_bytes = 0
        min_size: Optional[int] = None
        max_size: Optional[int] = None
        first_packet_at: Optional[datetime] = None
        last_packet_at: Optional[datetime] = None
        protocols_seen_set: set[str] = set()
        packets: list[dict[str, Any]] = []

        cap = None
        try:
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            # Open pcap with keep_packets=False to prevent unbounded RAM usage
            cap = pyshark.FileCapture(str(path), keep_packets=False, eventloop=loop)

            for pkt in cap:
                total_packets += 1
                pkt_len = int(pkt.length)
                total_frame_bytes += pkt_len

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

                direction = "-"
                flags_str = "-"
                p_payload_len = 0

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
                        direction = "A -> B"
                    elif src_p == port:
                        r2s_packets += 1
                        r2s_bytes += pkt_len
                        direction = "B -> A"

                    # TCP flags extraction
                    flags_val = 0
                    try:
                        raw_flags = getattr(tcp, "flags", None)
                        if raw_flags is not None:
                            flags_val = int(str(raw_flags), 0)
                    except Exception:
                        flags_val = 0

                    flag_names = []
                    if flags_val & 0x02:
                        flag_names.append("SYN")
                    if flags_val & 0x01:
                        flag_names.append("FIN")
                    if flags_val & 0x04:
                        flag_names.append("RST")
                    if flags_val & 0x08:
                        flag_names.append("PSH")
                    if flags_val & 0x10:
                        flag_names.append("ACK")
                    if flags_val & 0x20:
                        flag_names.append("URG")

                    flags_str = ", ".join(flag_names) if flag_names else "-"

                packets.append(
                    {
                        "index": total_packets,
                        "direction": direction,
                        "flags": flags_str,
                        "payload_bytes": p_payload_len,
                        "frame_bytes": pkt_len,
                    }
                )

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
        total_captured_bytes = total_frame_bytes
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
            "capture_file_bytes": file_bytes,
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
            "packets": packets,
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

        capture_interface = capture_doc.get("capture_interface") if capture_doc else None
        capture_status = capture_doc.get("capture_status") if capture_doc else None
        sender_id = capture_doc.get("device_a_id") if capture_doc else None
        receiver_id = capture_doc.get("device_b_id") if capture_doc else None
        profile_id = capture_doc.get("profile_id") if capture_doc else None

        exp_doc = None
        try:
            exp_doc = self.db["experiments"].find_one({"experiment_id": experiment_id})
        except Exception:
            exp_doc = None

        if exp_doc:
            if not sender_id:
                sender_id = exp_doc.get("sender_id")
            if not receiver_id:
                receiver_id = exp_doc.get("receiver_id")
            if not profile_id:
                profile_id = exp_doc.get("selected_profile_id")
            if not capture_interface and exp_doc.get("capture_interface"):
                capture_interface = exp_doc.get("capture_interface")
            if not capture_status and exp_doc.get("packet_capture", {}).get("capture_status"):
                capture_status = exp_doc.get("packet_capture", {}).get("capture_status")

        sender_name = None
        if sender_id:
            try:
                dev = self.db["devices"].find_one({"device_id": sender_id})
                if dev:
                    sender_name = dev.get("name")
            except Exception:
                pass
        if not sender_name and exp_doc:
            sender_name = exp_doc.get("sender_name")

        receiver_name = None
        if receiver_id:
            try:
                dev = self.db["devices"].find_one({"device_id": receiver_id})
                if dev:
                    receiver_name = dev.get("name")
            except Exception:
                pass
        if not receiver_name and exp_doc:
            receiver_name = exp_doc.get("receiver_name")

        profile_name = None
        if profile_id:
            try:
                prof = self.db["crypto_profiles"].find_one({"profile_id": profile_id})
                if prof:
                    profile_name = prof.get("name")
            except Exception:
                pass

        analysis["experiment_id"] = experiment_id
        if sender_id:
            analysis["sender_id"] = sender_id
        if sender_name:
            analysis["sender_name"] = sender_name
        if receiver_id:
            analysis["receiver_id"] = receiver_id
        if receiver_name:
            analysis["receiver_name"] = receiver_name
        if profile_id:
            analysis["profile_id"] = profile_id
        if profile_name:
            analysis["profile_name"] = profile_name
        if capture_interface:
            analysis["capture_interface"] = capture_interface
        if capture_status:
            analysis["capture_status"] = capture_status
        if capture_doc and capture_doc.get("capture_file_bytes"):
            analysis["capture_file_bytes"] = capture_doc.get("capture_file_bytes")

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
    def format_packet_table(packets: list[dict[str, Any]]) -> str:
        """Format detailed packet table."""
        header = f"{'#':<4}{'Direction':<11}{'Flags':<12}{'Payload(B)':<12}{'Frame(B)'}"
        divider = "-" * 54
        rows = [header, divider]
        for pkt in packets:
            idx = pkt.get("index", "")
            direction = pkt.get("direction", "-")
            flags = pkt.get("flags", "-")
            payload = pkt.get("payload_bytes", 0)
            frame = pkt.get("frame_bytes", 0)
            rows.append(f"{idx:<4}{direction:<11}{flags:<12}{payload:<12}{frame}")
        return "\n".join(rows)

    def format_summary(
        self_or_experiment_id: Any,
        experiment_id_or_analysis: Any = None,
        analysis_or_none: Optional[dict[str, Any]] = None,
        db: Any = None,
    ) -> str:
        """Format terminal summary matching Phase 10 / improved specifications."""
        if isinstance(self_or_experiment_id, TrafficAnalyzer):
            self_instance = self_or_experiment_id
            experiment_id = str(experiment_id_or_analysis)
            analysis = analysis_or_none or {}
            resolved_db = db or getattr(self_instance, "db", None)
        else:
            experiment_id = str(self_or_experiment_id)
            analysis = (
                experiment_id_or_analysis
                if isinstance(experiment_id_or_analysis, dict)
                else (analysis_or_none or {})
            )
            resolved_db = db

        if resolved_db is None:
            try:
                from database.connection import get_database

                resolved_db = get_database()
            except Exception:
                resolved_db = None

        # Resolve metadata if missing from analysis
        sender_id = analysis.get("sender_id")
        sender_name = analysis.get("sender_name")
        receiver_id = analysis.get("receiver_id")
        receiver_name = analysis.get("receiver_name")
        profile_id = analysis.get("profile_id")
        profile_name = analysis.get("profile_name")
        capture_interface = analysis.get("capture_interface")
        capture_status = analysis.get("capture_status")

        if resolved_db is not None:
            try:
                if not (sender_id and receiver_id and profile_id and capture_interface):
                    trap = resolved_db["traffic"].find_one({"experiment_id": experiment_id})
                    if trap:
                        sender_id = sender_id or trap.get("device_a_id")
                        receiver_id = receiver_id or trap.get("device_b_id")
                        profile_id = profile_id or trap.get("profile_id")
                        capture_interface = capture_interface or trap.get("capture_interface")
                        capture_status = capture_status or trap.get("capture_status")
                if not (sender_id and receiver_id and profile_id):
                    exp_doc = resolved_db["experiments"].find_one({"experiment_id": experiment_id})
                    if exp_doc:
                        sender_id = sender_id or exp_doc.get("sender_id")
                        receiver_id = receiver_id or exp_doc.get("receiver_id")
                        profile_id = profile_id or exp_doc.get("selected_profile_id")
                        sender_name = sender_name or exp_doc.get("sender_name")
                        receiver_name = receiver_name or exp_doc.get("receiver_name")

                # Resolve human-readable names dynamically
                if sender_id and not sender_name:
                    dev = resolved_db["devices"].find_one({"device_id": sender_id})
                    if dev:
                        sender_name = dev.get("name")
                if receiver_id and not receiver_name:
                    dev = resolved_db["devices"].find_one({"device_id": receiver_id})
                    if dev:
                        receiver_name = dev.get("name")
                if profile_id and not profile_name:
                    prof = resolved_db["crypto_profiles"].find_one({"profile_id": profile_id})
                    if prof:
                        profile_name = prof.get("name")
            except Exception:
                pass

        # Formatting displays for EXPERIMENT DETAILS
        if sender_name and sender_id and sender_name != sender_id:
            sender_disp = f"{sender_name} [{sender_id}]"
        elif sender_name or sender_id:
            sender_disp = f"{sender_name or sender_id}"
        else:
            sender_disp = "Unknown"

        if receiver_name and receiver_id and receiver_name != receiver_id:
            receiver_disp = f"{receiver_name} [{receiver_id}]"
        elif receiver_name or receiver_id:
            receiver_disp = f"{receiver_name or receiver_id}"
        else:
            receiver_disp = "Unknown"

        if profile_id and profile_name and profile_name != profile_id:
            profile_disp = f"{profile_id} - {profile_name}"
        elif profile_id or profile_name:
            profile_disp = f"{profile_id or profile_name}"
        else:
            profile_disp = "Unknown"

        msg_size = analysis.get("message_size_bytes")
        if msg_size is None:
            msg_size = analysis.get("original_message_size_bytes")
        msg_size_disp = f"{msg_size} B" if msg_size is not None else "Unknown"

        cap_iface_disp = str(capture_interface) if capture_interface else "Unknown"
        cap_status_disp = str(capture_status or "completed")
        analysis_status = analysis.get("analysis_status", "unknown")

        lines = [
            "================== TRAFFIC ANALYSIS ==================",
            "",
            "EXPERIMENT DETAILS",
            "-" * 54,
            f"{'Experiment ID':<18}: {experiment_id}",
            f"{'Sender (A)':<18}: {sender_disp}",
            f"{'Receiver (B)':<18}: {receiver_disp}",
            f"{'Crypto Profile':<18}: {profile_disp}",
            f"{'Message Size':<18}: {msg_size_disp}",
            f"{'Capture Interface':<18}: {cap_iface_disp}",
            "",
            "TRAFFIC SUMMARY",
            "-" * 54,
        ]

        if analysis_status == "completed":
            dur = analysis.get("traffic_duration_seconds", 0.0)
            dur_disp = f"{dur:.3f} s" if isinstance(dur, (int, float)) else f"{dur}"
            avg_size = analysis.get("average_packet_size_bytes", 0.0)
            avg_size_disp = (
                f"{avg_size:.2f} B"
                if isinstance(avg_size, (int, float))
                else f"{avg_size} B"
            )

            lines.extend(
                [
                    f"{'Total Packets':<18}: {analysis.get('total_packets', 0)}",
                    f"{'A -> B Packets':<18}: {analysis.get('sender_to_receiver_packets', 0)}",
                    f"{'B -> A Packets':<18}: {analysis.get('receiver_to_sender_packets', 0)}",
                    f"{'Data Packets':<18}: {analysis.get('application_data_packets', 0)}",
                    f"{'Captured Bytes':<18}: {analysis.get('total_captured_bytes', 0)} B",
                    f"{'TCP Payload':<18}: {analysis.get('tcp_payload_bytes', 0)} B",
                    f"{'Min Packet Size':<18}: {analysis.get('min_packet_size_bytes', 0)} B",
                    f"{'Max Packet Size':<18}: {analysis.get('max_packet_size_bytes', 0)} B",
                    f"{'Avg Packet Size':<18}: {avg_size_disp}",
                    f"{'Retransmissions':<18}: {analysis.get('tcp_retransmissions', 0)}",
                    f"{'Traffic Duration':<18}: {dur_disp}",
                    "",
                    "NETWORK OVERHEAD",
                    "-" * 54,
                    f"{'Overhead Bytes':<18}: {analysis.get('network_overhead_bytes', 0)} B",
                    f"{'Overhead Percent':<18}: {analysis.get('network_overhead_percent', 0.0):.2f}%",
                ]
            )

            packets = analysis.get("packets", [])
            if packets:
                lines.extend(
                    [
                        "",
                        "PACKET DETAILS",
                        "-" * 54,
                        TrafficAnalyzer.format_packet_table(packets),
                    ]
                )

            lines.extend(
                [
                    "-" * 54,
                    f"{'Capture Status':<18}: {cap_status_disp}",
                    f"{'Analysis Status':<18}: {analysis_status}",
                    "=" * 54,
                ]
            )
        else:
            err = analysis.get("analysis_error", "Unknown error")
            lines.extend(
                [
                    f"{'Status':<18}: {analysis_status}",
                    f"{'Error':<18}: {err}",
                    "-" * 54,
                    f"{'Capture Status':<18}: {cap_status_disp}",
                    f"{'Analysis Status':<18}: {analysis_status}",
                    f"{'Error':<18}: {err}",
                    "=" * 54,
                ]
            )

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

