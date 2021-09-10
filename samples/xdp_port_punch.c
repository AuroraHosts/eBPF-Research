#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp_punch")
int xdp_port_punch(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    
    if ((void *) ip + sizeof(*ip) <= data_end) {
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *) ip + sizeof(*ip);
            if ((void *) tcp + sizeof(*tcp) <= data_end) {
                if (htons(tcp->dest) != 22) {
                    return XDP_DROP;
                }
            }
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";