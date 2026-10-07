"""Phase 9 – TShark-based packet capture wrapper.

Design notes
------------
* Uses ``subprocess`` without ``shell=True`` for safety.
* The capture is started before the sender-receiver exchange and stopped
  after it completes (or fails), using a try/finally or context manager so
  that TShark is always cleaned up.
* The loopback interface is chosen automatically for localhost communication,
  because selecting a Wi-Fi/Ethernet interface while both endpoints talk via
  127.0.0.1 would result in an empty capture.
* No new third-party Python packages are required: only stdlib modules.
* TShark is an *external* system dependency.  The code degrades gracefully when
  TShark is absent and raises ``TSharkNotFoundError`` with clear instructions.

Phase 10 compatibility
----------------------
``PacketCapture`` writes a standard ``.pcapng`` file that PyShark (Phase 10)
can open directly.  Metadata recorded in MongoDB during Phase 9 is structured
to match the field names that Phase 10 will consume.

Configuration
-------------
Two environment / .env variables are respected (in addition to SERVER_HOST and
SERVER_PORT which are read from the existing config):

    CAPTURE_INTERFACE   Name of the capture interface to use.
                        Defaults to the loopback interface for the current OS.
                        Run ``python -m capture.packet_capture list`` to see
                        available names.

    CAPTURE_DIR         Directory for .pcapng files.
                        Defaults to ``captures/`` next to the project root.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path
from typing import Any, Generator

from config import get_env

# Indian Standard Time (IST = UTC+05:30)
IST = ZoneInfo("Asia/Kolkata")


# ---------------------------------------------------------------------------
# Project root – one directory above this file (capture/packet_capture.py)
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TSharkNotFoundError(RuntimeError):
    """Raised when the tshark binary cannot be found on PATH."""


class CaptureInterfaceError(RuntimeError):
    """Raised when the requested capture interface is invalid or inaccessible."""


class CaptureError(RuntimeError):
    """Raised when TShark fails to start, crashes unexpectedly, or produces
    no output."""


# ---------------------------------------------------------------------------
# Interface discovery
# ---------------------------------------------------------------------------

def _find_tshark() -> str:
    """Return the absolute path to the tshark binary or raise TSharkNotFoundError."""
    # Honour explicit override first (useful when tshark is not on PATH)
    explicit = get_env("TSHARK_PATH")
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)

    # Common macOS Wireshark App installation path
    mac_app = Path("/Applications/Wireshark.app/Contents/MacOS/tshark")
    if mac_app.is_file():
        return str(mac_app)

    # shutil.which searches PATH
    found = shutil.which("tshark")
    if found:
        return found

    raise TSharkNotFoundError(
        "tshark could not be found.\n"
        "Install Wireshark (which bundles tshark) or install tshark separately:\n"
        "  macOS:  brew install --cask wireshark\n"
        "  Linux:  sudo apt install tshark  (or equivalent)\n"
        "  Win:    https://www.wireshark.org/download.html\n"
        "Then ensure tshark is on PATH, or set TSHARK_PATH=/path/to/tshark in .env"
    )


def list_interfaces() -> list[dict[str, str]]:
    """Return a list of capture interfaces visible to TShark.

    Each element is a dict with keys:
        ``index``       TShark's 1-based interface number (string)
        ``name``        Interface name usable in -i flag
        ``description`` Human-readable label (may be empty)

    Raises TSharkNotFoundError if tshark is not installed.
    """
    tshark = _find_tshark()
    try:
        result = subprocess.run(
            [tshark, "-D"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired as exc:
        raise CaptureError("tshark -D timed out") from exc
    except OSError as exc:
        raise TSharkNotFoundError(f"Failed to execute tshark: {exc}") from exc

    interfaces: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Format: "1. eth0 (Ethernet adapter)"  or  "1. \Device\NPF_... (description)"
        parts = line.split(".", 1)
        if len(parts) != 2:
            continue
        index = parts[0].strip()
        rest = parts[1].strip()
        # rest may be "lo0 (Loopback)" or just "lo0"
        if " " in rest:
            name, desc = rest.split(" ", 1)
            desc = desc.strip("() ")
        else:
            name = rest
            desc = ""
        interfaces.append({"index": index, "name": name, "description": desc})
    return interfaces


def get_loopback_interface() -> str:
    """Return the loopback interface name appropriate for the current OS.

    On macOS the loopback is ``lo0``.
    On Linux it is ``lo``.
    On Windows TShark exposes ``\\Device\\NPF_Loopback`` – this function
    searches the interface list for a device whose description contains
    "loopback" (case-insensitive) and returns its name.

    If the automatic selection fails the function returns the platform
    default and logs a warning so the user can override via CAPTURE_INTERFACE.
    """
    system = platform.system()

    if system == "Darwin":
        return "lo0"

    if system == "Linux":
        return "lo"

    if system == "Windows":
        try:
            ifaces = list_interfaces()
        except TSharkNotFoundError:
            return r"\Device\NPF_Loopback"  # best guess
        for iface in ifaces:
            combined = (iface["name"] + " " + iface["description"]).lower()
            if "loopback" in combined or "npcap loopback" in combined:
                return iface["name"]
        # fallback
        return r"\Device\NPF_Loopback"

    # Unknown OS – try "lo" and hope for the best
    return "lo"


# ---------------------------------------------------------------------------
# Capture directory
# ---------------------------------------------------------------------------

def _resolve_capture_dir() -> Path:
    """Return the absolute path to the captures directory, creating it if needed."""
    env_dir = get_env("CAPTURE_DIR")
    if env_dir:
        d = Path(env_dir)
    else:
        d = _PROJECT_ROOT / "captures"
    d.mkdir(parents=True, exist_ok=True)
    return d.resolve()


def _capture_filename(experiment_id: str, profile_id: str, message_size_bytes: int) -> str:
    """Build a deterministic, human-readable .pcapng filename.

    Format:  experiment_<exp_id>_<profile_id>_<msg_size>B.pcapng

    Special characters in profile_id (e.g. "/" or " ") are replaced with "_"
    so the filename is safe on all OSes.
    """
    safe_profile = profile_id.replace("/", "_").replace(" ", "_").replace("\\", "_")
    return f"experiment_{experiment_id}_{safe_profile}_{message_size_bytes}B.pcapng"


# ---------------------------------------------------------------------------
# Core capture class
# ---------------------------------------------------------------------------

class PacketCapture:
    """Manage a single TShark capture session tied to one experiment.

    Typical usage (context manager – preferred)
    -------------------------------------------
    ::

        with PacketCapture(experiment_id, profile_id, message_size_bytes) as cap:
            run_client(...)   # or run one send/receive exchange

        # After the ``with`` block the capture is stopped and saved.
        print(cap.capture_file)   # relative path to .pcapng

    Manual usage
    ------------
    ::

        cap = PacketCapture(experiment_id, profile_id, message_size_bytes)
        cap.start()
        try:
            run_client(...)
        finally:
            cap.stop()

    Parameters
    ----------
    experiment_id:
        The experiment UUID/string used to name the file and the MongoDB entry.
    profile_id:
        The winning crypto profile ID (used in the filename only).
    message_size_bytes:
        Size of the message payload (used in the filename only).
    interface:
        Capture interface name.  If ``None`` the value of the
        ``CAPTURE_INTERFACE`` environment variable is used; if that is also
        absent the OS loopback interface is selected automatically.
    capture_filter:
        A libpcap-style capture filter string.  Defaults to
        ``tcp port <SERVER_PORT>`` derived from the existing configuration.
    startup_wait_seconds:
        Seconds to wait after launching TShark before starting the experiment
        so that TShark is ready to capture the first SYN packet.
    """

    def __init__(
        self,
        experiment_id: str,
        profile_id: str = "unknown-profile",
        message_size_bytes: int = 0,
        *,
        device_a_id: str | None = None,
        device_b_id: str | None = None,
        interface: str | None = None,
        capture_filter: str | None = None,
        startup_wait_seconds: float = 0.5,
    ) -> None:
        self.experiment_id = experiment_id
        self.profile_id = profile_id
        self.message_size_bytes = message_size_bytes
        self.device_a_id = device_a_id
        self.device_b_id = device_b_id
        self.startup_wait_seconds = startup_wait_seconds

        # ── Interface ───────────────────────────────────────────────────────
        # Priority: constructor arg > CAPTURE_INTERFACE env var > loopback default
        self.interface: str = (
            interface
            or get_env("CAPTURE_INTERFACE")
            or get_loopback_interface()
        )

        # ── Capture filter ───────────────────────────────────────────────────
        port = int(get_env("SERVER_PORT", "5000") or "5000")
        self.capture_filter: str = capture_filter or f"tcp port {port}"

        # ── Output file ──────────────────────────────────────────────────────
        capture_dir = _resolve_capture_dir()
        filename = _capture_filename(experiment_id, profile_id, message_size_bytes)
        self._abs_path: Path = capture_dir / filename

        # Project-relative path for storage in MongoDB (avoids machine-specific
        # absolute paths that break when the project is moved).
        try:
            self.capture_file: str = str(self._abs_path.relative_to(_PROJECT_ROOT))
        except ValueError:
            # capture dir is outside the project root – store absolute path
            self.capture_file = str(self._abs_path)

        # ── Runtime state ────────────────────────────────────────────────────
        self._process: subprocess.Popen[bytes] | None = None
        self._tshark_bin: str | None = None
        self._started_at: datetime | None = None
        self._stopped_at: datetime | None = None
        self._live_output: bool = False
        self.capture_status: str = "not_started"
        self.capture_error: str | None = None

    # ── Context manager protocol ─────────────────────────────────────────────

    def __enter__(self) -> "PacketCapture":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        # Always stop capture; preserve the file even if the experiment failed.
        self.stop(experiment_failed=(exc_type is not None))

    # ── Public methods ───────────────────────────────────────────────────────

    def start(self, live_output: bool = False) -> None:
        """Launch TShark and wait briefly for it to initialise.

        Raises
        ------
        TSharkNotFoundError
            When tshark is not installed.
        CaptureError
            When TShark exits immediately (bad interface, permissions, etc.).
        """
        self._live_output = live_output
        tshark = _find_tshark()
        self._tshark_bin = tshark

        # Build the tshark command.
        # -i  : capture interface
        # -f  : capture filter (libpcap BPF syntax)
        # -w  : output file in pcapng format
        # -q  : quiet (suppress per-packet output to stderr)
        # --no-promiscuous-mode : avoid failures in restrictive environments
        #                         (promiscuous mode is not needed for loopback)
        cmd: list[str] = [
            tshark,
            "-i", self.interface,
            "-f", self.capture_filter,
            "-w", str(self._abs_path),
        ]
        if live_output:
            cmd.extend(["-P", "-l"])
        else:
            cmd.append("-q")

        if not live_output:
            print(f"[CAPTURE] Interface: {self.interface}", flush=True)
            print(f"[CAPTURE] Filter: {self.capture_filter}", flush=True)

        try:
            # stderr=subprocess.PIPE keeps TShark's diagnostic messages off the
            # terminal while still letting us read them for error diagnosis.
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE if live_output else subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=live_output or None,
                bufsize=1 if live_output else -1,
            )
        except FileNotFoundError as exc:
            raise TSharkNotFoundError(
                f"Could not launch tshark at '{tshark}': {exc}"
            ) from exc
        except PermissionError as exc:
            raise CaptureError(
                f"Permission denied when launching tshark.  "
                f"On macOS/Linux you may need to run as root or add your user to "
                f"the 'wireshark'/'access_bpf' group: {exc}"
            ) from exc

        # Give TShark a moment to open the interface before we start sending
        # packets.  Without this the first SYN may be missed.
        time.sleep(self.startup_wait_seconds)

        # Check that tshark did not immediately exit (bad interface, bad filter…)
        if self._process.poll() is not None:
            stderr_output = b""
            if self._process.stderr:
                stderr_output = self._process.stderr.read()
            self._process = None
            self.capture_status = "failed"
            self.capture_error = stderr_output.decode(errors="replace").strip()
            raise CaptureError(
                f"TShark exited immediately (code {self._process and self._process.returncode}).\n"
                f"Interface '{self.interface}' may be invalid or require elevated privileges.\n"
                f"TShark stderr: {self.capture_error}\n\n"
                f"To list available interfaces run:\n"
                f"  python -m capture.packet_capture list\n"
                f"Then set CAPTURE_INTERFACE=<name> in your .env file."
            )

        self._started_at = datetime.now(IST)
        self.capture_status = "running"
        if not live_output:
            print("[CAPTURE] Started", flush=True)

    def stop(self, *, experiment_failed: bool = False) -> None:
        """Stop TShark gracefully and record final status.

        Sends SIGINT (Ctrl-C equivalent) first; falls back to SIGTERM, then
        SIGKILL if the process does not terminate.

        Parameters
        ----------
        experiment_failed:
            When ``True`` the capture status is set to ``"capture_with_error"``
            if the file exists and has content, or ``"failed"`` otherwise.
        """
        if self._process is None:
            # start() was never called or already cleaned up
            return

        proc = self._process
        self._process = None  # prevent double-stop

        # ── Ask TShark to finish writing the capture file ────────────────────
        # SIGINT causes TShark to flush and close the pcapng file cleanly.
        try:
            if sys.platform == "win32":
                proc.send_signal(signal.CTRL_C_EVENT)  # type: ignore[attr-defined]
            else:
                proc.send_signal(signal.SIGINT)
        except ProcessLookupError:
            pass  # process already exited

        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            # SIGINT was not enough – escalate
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        self._stopped_at = datetime.now(IST)

        # Read any remaining stderr for diagnostics (non-blocking)
        stderr_text = ""
        if proc.stderr:
            try:
                stderr_text = proc.stderr.read().decode(errors="replace")
            except Exception:
                pass

        # ── Assess capture file ──────────────────────────────────────────────
        file_ok = self._abs_path.exists() and self._abs_path.stat().st_size > 0

        if not file_ok:
            self.capture_status = "empty" if self._abs_path.exists() else "failed"
            self.capture_error = (
                f"Capture file is missing or empty.  "
                f"Check that the interface '{self.interface}' carries the "
                f"expected traffic.  TShark output: {stderr_text.strip()}"
            )
            print(
                f"[CAPTURE] Warning: {self.capture_status} — {self.capture_error}",
                flush=True,
            )
        elif experiment_failed:
            self.capture_status = "capture_with_error"
            print(
                "[CAPTURE] Stopped (experiment failed; capture preserved for inspection)",
                flush=True,
            )
        else:
            self.capture_status = "completed"
            if not self._live_output:
                print("[CAPTURE] Stopped", flush=True)

        if file_ok and not self._live_output:
            print(f"[CAPTURE] Saved: {self.capture_file}", flush=True)

    # ── MongoDB metadata ─────────────────────────────────────────────────────

    def metadata(self) -> dict[str, Any]:
        """Return a dict suitable for storing in the ``traffic`` collection.

        Fields are chosen to be useful to Phase 10 (PyShark analysis) without
        storing sensitive cryptographic secrets.
        """
        info: dict[str, Any] = {
            "experiment_id": self.experiment_id,
            "profile_id": self.profile_id,
            "device_a_id": self.device_a_id,
            "device_b_id": self.device_b_id,
            "message_size_bytes": self.message_size_bytes,
            "capture_file": self.capture_file,
            "capture_interface": self.interface,
            "capture_filter": self.capture_filter,
            "capture_status": self.capture_status,
            "capture_started_at": self._started_at,
            "capture_stopped_at": self._stopped_at,
            "capture_duration_seconds": (
                round((self._stopped_at - self._started_at).total_seconds(), 3)
                if self._started_at and self._stopped_at
                else 0.0
            ),
            "capture_file_bytes": (
                self._abs_path.stat().st_size
                if self._abs_path.exists()
                else 0
            ),
            "capture_file_sha256": (
                hashlib.sha256(self._abs_path.read_bytes()).hexdigest()
                if self._abs_path.exists()
                else None
            ),
            "created_at": datetime.now(IST),
        }
        if self.capture_error:
            info["capture_error"] = self.capture_error

        return info

    def persist_to_db(self) -> None:
        """Write Phase 9 capture metadata into the dedicated ``traffic`` MongoDB collection.

        Creates one traffic document per capture/experiment, linked using experiment_id.
        Also retains a reference in experiments collection if existing experiment doc exists.
        """
        try:
            from database.connection import get_database
            db = get_database()
            meta = self.metadata()

            # Store in dedicated iot_security.traffic collection
            db["traffic"].update_one(
                {"experiment_id": self.experiment_id},
                {"$set": meta},
                upsert=True,
            )

            # Keep reference in experiments collection if the document exists
            db["experiments"].update_one(
                {"experiment_id": self.experiment_id},
                {
                    "$set": {
                        "packet_capture": {
                            "capture_file": self.capture_file,
                            "capture_status": self.capture_status,
                        }
                    }
                },
                upsert=False,
            )
        except Exception as exc:
            print(
                f"[CAPTURE] Warning: could not persist capture metadata to MongoDB: {exc}",
                flush=True,
            )


# ---------------------------------------------------------------------------
# CLI helpers (python -m capture.packet_capture)
# ---------------------------------------------------------------------------

def _cmd_list_interfaces() -> None:
    """Print all available TShark interfaces."""
    try:
        ifaces = list_interfaces()
    except TSharkNotFoundError as exc:
        print(f"[CAPTURE] Error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    if not ifaces:
        print("[CAPTURE] No interfaces found.", file=sys.stderr)
        raise SystemExit(1)

    print("[CAPTURE] Available capture interfaces:")
    for iface in ifaces:
        desc = f"  ({iface['description']})" if iface["description"] else ""
        print(f"  {iface['index']:>3}. {iface['name']}{desc}")

    loopback = get_loopback_interface()
    print(f"\n[CAPTURE] Detected loopback interface for this OS: {loopback}")
    print("[CAPTURE] Set CAPTURE_INTERFACE=<name> in .env to override.")


if __name__ == "__main__":
    # Allow: python -m capture.packet_capture list
    if len(sys.argv) >= 2 and sys.argv[1] == "list":
        _cmd_list_interfaces()
    else:
        print("Usage: python -m capture.packet_capture list", file=sys.stderr)
        raise SystemExit(1)

