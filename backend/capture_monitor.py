"""
Phase 9 - Capturing traffic using Wireshark
Captures TCP packets captured during transmission

Run from backend/: python capture_monitor.py
"""

import subprocess
import select
import time
import sys
import re
import signal
from pathlib import Path

from capture.packet_capture import PacketCapture, get_loopback_interface
from config import get_env
from database.connection import get_database

running = True

def handle_sigint(signum, frame):
    global running
    print("\n[NETWORK] Shutting down monitor...")
    running = False

signal.signal(signal.SIGINT, handle_sigint)

def run_monitor():
    db = get_database()
    
    while running:
        temp_exp = f"temp_{int(time.time())}"
        
        cap = PacketCapture(
            experiment_id=temp_exp,
            profile_id="unknown",
            message_size_bytes=0,
        )
        
        print("================ NETWORK CAPTURE ================", flush=True)
        print(f"Interface : {cap.interface}", flush=True)
        print(f"Filter    : {cap.capture_filter}", flush=True)
        
        try:
            cap.start(live_output=True)
        except Exception as e:
            print(f"[NETWORK] Error starting capture: {e}")
            break
            
        print("Status    : Listening...", flush=True)
        proc = cap._process
        
        packets_seen = 0
        last_packet_time = time.time()
        
        try:
            while running:
                r, _, _ = select.select([proc.stdout], [], [], 0.5)
                if r:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    
                    line = line.strip()
                    if not line:
                        continue
                    
                    # TShark output parsing:
                    # e.g.: 1 0.000000 127.0.0.1 → 127.0.0.1 TCP 68 54321 → 5000 [SYN] ...
                    # or:   5 0.000395 127.0.0.1 → 127.0.0.1 RSL 309 [Malformed Packet]
                    # Format: [NETWORK] <src_ip>:<src_port> -> <dst_ip>:<dst_port> TCP <detail>
                    m = re.search(
                        r'([\d\.]+)\s*(?:→|->)\s*([\d\.]+)\s+(?:TCP|RSL|\S+)\s+(\d+)\s+.*?'
                        r'(?:(\d+)\s*(?:→|->)\s*(\d+))?'
                        r'(.*)',
                        line,
                    )
                    if m:
                        src_ip = m.group(1)
                        dst_ip = m.group(2)
                        length = m.group(3)
                        sport = m.group(4)
                        dport = m.group(5)
                        rest = m.group(6)

                        # If sport and dport were not matched by the previous group, search in rest
                        if not sport or not dport:
                            port_m = re.search(r'(\d+)\s*(?:→|->)\s*(\d+)', rest)
                            if port_m:
                                sport = port_m.group(1)
                                dport = port_m.group(2)

                        sport = sport or "unknown"
                        dport = dport or "5000"

                        if "[SYN]" in rest:
                            detail = "SYN"
                        elif "[FIN" in rest:
                            detail = "FIN"
                        else:
                            detail = f"{length} bytes"

                        print(f"[NETWORK] {src_ip}:{sport} -> {dst_ip}:{dport} TCP {detail}", flush=True)
                    else:
                        print(f"[NETWORK] {line}", flush=True)
                        
                    packets_seen += 1
                    last_packet_time = time.time()
                else:
                    if packets_seen > 0 and time.time() - last_packet_time > 1.5:
                        break
        except KeyboardInterrupt:
            break
            
        cap.stop()
        
        if not running:
            break
            
        if packets_seen > 0:
            recent_exp = db["experiments"].find_one({}, sort=[("_id", -1)])
            if recent_exp:
                real_exp_id = recent_exp.get("experiment_id")
                profile_id = recent_exp.get("observed_results", {}).get("profile_id_used") or recent_exp.get("selected_profile_id", "unknown")
                msg_size = recent_exp.get("observed_results", {}).get("message_size_bytes") or recent_exp.get("message_size_bytes", 0)
                
                cap.experiment_id = real_exp_id
                cap.profile_id = profile_id
                cap.message_size_bytes = msg_size
                cap.device_a_id = recent_exp.get("observed_results", {}).get("sender_id", "unknown")
                cap.device_b_id = recent_exp.get("observed_results", {}).get("receiver_id", "unknown")
                
                old_path = cap._abs_path
                new_filename = f"experiment_{real_exp_id}_{profile_id.replace('/', '_').replace(' ', '_')}_{msg_size}B.pcapng"
                new_path = old_path.parent / new_filename
                
                if old_path.exists():
                    old_path.rename(new_path)
                    cap._abs_path = new_path
                    cap.capture_file = f"captures/{new_filename}"
                
                cap.persist_to_db()
        else:
            if cap._abs_path.exists():
                cap._abs_path.unlink()

if __name__ == "__main__":
    run_monitor()
