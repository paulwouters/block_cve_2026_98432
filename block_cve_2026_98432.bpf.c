#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

/* Constants defined in standard networking if missing from vmlinux.h */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

SEC("xdp")
int xdp_drop_ipv4_options(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Parse and bounds-check Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Filter for IPv4 only */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse and bounds-check base IPv4 header */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    /* Filter for TCP only */
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /*
     * The standard IPv4 header is 20 bytes (ihl == 5).
     * Any ihl > 5 indicates the presence of IPv4 options.
     * Dropping here stops the packet before it enters the TCP stack
     * where the CVE-2026-98432 ireq->ireq_opt UAF race is triggered.
     */
    if (iph->ihl > 5)
        return XDP_DROP;

    return XDP_PASS;
}