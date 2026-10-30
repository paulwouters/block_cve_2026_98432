
Hacked in a short time with Gemini - use at own risk !

This is an attempt to block CVE-2026-98432 on machines you cannot instantly
upgrade. If you can upgrade and reboot your machine, stop reading here and
go do that instead.

Otherwise:

# Prep

## install all clang / kernel / bpf headers / bpftool

```
sudo dnf install -y kernel-headers libbpf-devel bpftool
```

# Generate vmlinux.h

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

# Compile ebpf

```
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c block_cve_2026_98432.bpf.c -o block_cve_2026_98432.o
```

# Attach to external interface, eg eth0

```
ip link set dev eth0 xdpgeneric obj block_cve_2026_98432.o sec xdp
```

# Check Status

```
ip link show dev eth0

```
## Example output:

```
# ip link show dev eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric qdisc fq_codel master br0 state UP mode DEFAULT group default qlen 1000
    link/ether 54:04:xx:xx:xx:xx brd ff:ff:ff:ff:ff:ff
    prog/xdp id 507 name xdp_drop_ipv4_o tag 8ec1d1e23832caaf jited 
    altname enp0s25
    altname enx5404a60bcf0e
```

# Verify it works

From another machine install python scapy (sudo dnf install python3-scapy or pip install scapy)

sudo python3 verify_xdp_filter.py 192.168.1.1 80

## example output

```
# python verify_xdp_filter.py 193.xxx.xxx.xxx 22
/usr/lib/python3.15/site-packages/scapy/layers/tls/crypto/groups.py:25: CryptographyDeprecationWarning: Diffie-Hellman over finite fields (FFDH) is deprecated and support will be removed in a future release. Use a more modern key exchange algorithm.
  from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
[*] Target: 193.xxx.xxx.xxx:22

[+] 1. Sending baseline TCP SYN (ihl = 5, no IP options)...
    [PASS] Received response: TCP flags [SA] (Host is reachable)

[+] 2. Sending TCP SYN with IPv4 options (ihl = 6)...
    Crafted IP Header Length: 24 bytes (ihl=6)

[RESULT] SUCCESS: Packet dropped silently.
         The XDP filter intercepted and dropped the packet containing IPv4 options.

```

A vulnerable machine looks like:

```
# python verify_xdp_filter.py 127.0.0.1 22
/usr/lib/python3.15/site-packages/scapy/layers/tls/crypto/groups.py:25: CryptographyDeprecationWarning: Diffie-Hellman over finite fields (FFDH) is deprecated and support will be removed in a future release. Use a more modern key exchange algorithm.
  from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
[*] Target: 127.0.0.1:22

[+] 1. Sending baseline TCP SYN (ihl = 5, no IP options)...
    [PASS] Received response: TCP flags [SA] (Host is reachable)

[+] 2. Sending TCP SYN with IPv4 options (ihl = 6)...
    Crafted IP Header Length: 24 bytes (ihl=6)

[RESULT] FAILURE: Received reply: TCP flags [SA].
         The packet reached the TCP stack! The XDP filter is NOT active on the ingress path.

```


# Remove it

```
sudo ip link set dev eth0 xdpgeneric off
```

