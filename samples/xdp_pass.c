#include <linux/bpf.h>

SEC("xdp_pass")
int pass_filter(struct *xdp_md ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";