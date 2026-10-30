#!/usr/bin/env python3
import sys
from scapy.all import IP, TCP, IPOption_NOP, sr1, conf, raw

# Disable Scapy verbose output
conf.verb = 0

def test_target(target_ip: str, target_port: int = 80, timeout: int = 3):
    print(f"[*] Target: {target_ip}:{target_port}")

    # 1. Baseline / Control Packet (Standard TCP SYN)
    print("\n[+] 1. Sending baseline TCP SYN (ihl = 5, no IP options)...")
    base_pkt = IP(dst=target_ip) / TCP(dport=target_port, flags="S", seq=1000)
    
    reply = sr1(base_pkt, timeout=timeout)
    if reply:
        flags = reply.sprintf("%TCP.flags%")
        print(f"    [PASS] Received response: TCP flags [{flags}] (Host is reachable)")
    else:
        print("    [WARN] No response to baseline SYN. Target port may be closed or firewalled.")

    # 2. Test Packet with IPv4 Options (Forces ihl = 6)
    # Adding 4 NOP options increases the IPv4 header length from 20 to 24 bytes
    print("\n[+] 2. Sending TCP SYN with IPv4 options (ihl = 6)...")
    opt_pkt = (
        IP(dst=target_ip, options=[IPOption_NOP(), IPOption_NOP(), IPOption_NOP(), IPOption_NOP()])
        / TCP(dport=target_port, flags="S", seq=1001)
    )

    # Force packet build so Scapy populates ihl and checksums
    built_ip = IP(raw(opt_pkt))
    print(f"    Crafted IP Header Length: {built_ip.ihl * 4} bytes (ihl={built_ip.ihl})")

    reply_opt = sr1(opt_pkt, timeout=timeout)
    if reply_opt is None:
        print("\n[RESULT] SUCCESS: Packet dropped silently.")
        print("         The XDP filter intercepted and dropped the packet containing IPv4 options.")
    else:
        flags = reply_opt.sprintf("%TCP.flags%")
        print(f"\n[RESULT] FAILURE: Received reply: TCP flags [{flags}].")
        print("         The packet reached the TCP stack! The XDP filter is NOT active on the ingress path.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: sudo {sys.argv[0]} <TARGET_IP> [TARGET_PORT]")
        sys.exit(1)

    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    test_target(target, port)