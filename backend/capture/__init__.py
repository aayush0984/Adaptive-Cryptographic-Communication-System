"""Phase 9 – Wireshark/TShark packet capture package.

Public API
----------
``PacketCapture``  – context manager that starts TShark before the
                     sender-receiver exchange and stops it afterwards.

``list_interfaces``  – enumerate the capture interfaces visible to TShark.

``get_loopback_interface``  – return the OS-appropriate loopback interface
                              name (``lo0`` on macOS, ``lo`` on Linux, a
                              NPF loopback device on Windows).
"""

from capture.packet_capture import PacketCapture, list_interfaces, get_loopback_interface

__all__ = ["PacketCapture", "list_interfaces", "get_loopback_interface"]

