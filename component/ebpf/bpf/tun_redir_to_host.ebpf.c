#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>

struct {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __type(key,         __u8[ETH_ALEN]);
  __type(value,       __u32);
  __uint(max_entries, 64);
} hosts_map SEC(".maps");

SEC("tc/tun_redirect_to_host")
int tc_tun_redirect_to_host(struct __sk_buff *skb) {
  void *data          = (void *)(long)skb->data;
  void *data_end      = (void *)(long)skb->data_end;
  struct ethhdr *eth  = data;

  if ((void *)(eth + 1) > data_end) {
    return TC_ACT_OK;
  }

  __u32 *host_ifindex = bpf_map_lookup_elem(&hosts_map, eth->h_dest);
  if (!host_ifindex) {
    return TC_ACT_OK;
  }

  return bpf_redirect(*host_ifindex, BPF_F_INGRESS);
}

char _license[] SEC("license") = "GPL";
