#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include "helper.h"

struct params {
  __u32   clash_mark;
  __u32   tun_ifindex;
  __u32   fake_ip4_prefix;
  __be32  fake_ip6_prefix[2];
  __u8    tun_mac[ETH_ALEN];
  __u8    _pad[2];
};

struct {
  __uint(type,        BPF_MAP_TYPE_ARRAY);
  __type(key,         __u32);
  __type(value,       struct params);
  __uint(max_entries, 1);
} params_map SEC(".maps");

SEC("tc_clash_redirect_to_tun")
int tc_tun_func(struct __sk_buff *skb) {
  __u32 key = 0;
  struct params *vars = bpf_map_lookup_elem(&params_map, &key);
  if (!vars) {
    return TC_ACT_OK;
  }

  if (skb->mark == vars->clash_mark) {
    return TC_ACT_OK;
  }

  void *data          = (void *)(long)skb->data;
  void *data_end      = (void *)(long)skb->data_end;
  struct ethhdr *eth  = data;

  if ((void *)(eth + 1) > data_end) {
    return TC_ACT_OK;
  }

  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
      return TC_ACT_OK;
    }

    __u32 dst_ip_h = bpf_ntohl(iph->daddr);

    if (iph->protocol == IPPROTO_ICMP) {
      struct icmphdr *icmp = (struct icmphdr *)(iph + 1);
      if ((void *)(icmp + 1) > data_end) {
        return TC_ACT_OK;
      }
      if (icmp->type == ICMP_ECHOREPLY) {
        return TC_ACT_OK;
      }
      if (icmp->type == ICMP_ECHO && (dst_ip_h & 0xffff0000) != vars->fake_ip4_prefix) {
        return TC_ACT_OK;
      }
    }

    if (IN_LOOPBACK(dst_ip_h) || IN_PRIVATE(dst_ip_h) || IN_MULTICAST(dst_ip_h) || dst_ip_h == INADDR_BROADCAST) {
      return TC_ACT_OK;
    }
  } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end) {
      return TC_ACT_OK;
    }

    if (ip6h->nexthdr == IPPROTO_ICMPV6) {
      struct icmp6hdr *icmp = (struct icmp6hdr *)(ip6h + 1);
      if ((void *)(icmp + 1) > data_end) {
        return TC_ACT_OK;
      }
      if (icmp->icmp6_type == ICMPV6_ECHO_REPLY) {
        return TC_ACT_OK;
      }
      if (icmp->icmp6_type == ICMPV6_ECHO_REQUEST &&
          (ip6h->daddr.in6_u.u6_addr32[0] != vars->fake_ip6_prefix[0] ||
           ip6h->daddr.in6_u.u6_addr32[1] != vars->fake_ip6_prefix[1])) {
        return TC_ACT_OK;
      }
    }

    if (IN6_IS_ADDR_LOOPBACK(&ip6h->daddr)  ||
        IN6_IS_ADDR_LINKLOCAL(&ip6h->daddr) ||
        IN6_IS_ADDR_SITELOCAL(&ip6h->daddr) ||
        IN6_IS_ADDR_MULTICAST(&ip6h->daddr)) {
      return TC_ACT_OK;
    }
  } else {
    return TC_ACT_OK;
  }

  bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), vars->tun_mac, ETH_ALEN, 0);

  // return bpf_redirect(vars->tun_ifindex, BPF_F_INGRESS); // __bpf_rx_skb
  return bpf_redirect(vars->tun_ifindex, 0); // __bpf_tx_skb / __dev_xmit_skb
}

// below is to use the new Variable API and rather than traditional bpf maps.
// the Variable API requires kernel >= v5.5.
const volatile __u32  clash_mark, tun_ifindex, fake_ip4_prefix;
const volatile __be32 fake_ip6_prefix[2];
const          __u8   tun_mac[ETH_ALEN];

SEC("tc_clash_redirect_to_tun_5_5")
int tc_tun_5_5_func(struct __sk_buff *skb) {
  if (skb->mark == clash_mark) {
    return TC_ACT_OK;
  }

  void *data          = (void *)(long)skb->data;
  void *data_end      = (void *)(long)skb->data_end;
  struct ethhdr *eth  = data;

  if ((void *)(eth + 1) > data_end) {
    return TC_ACT_OK;
  }

  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
      return TC_ACT_OK;
    }

    __u32 dst_ip_h = bpf_ntohl(iph->daddr);

    if (iph->protocol == IPPROTO_ICMP) {
      struct icmphdr *icmp = (struct icmphdr *)(iph + 1);
      if ((void *)(icmp + 1) > data_end) {
        return TC_ACT_OK;
      }
      if (icmp->type == ICMP_ECHOREPLY) {
        return TC_ACT_OK;
      }
      if (icmp->type == ICMP_ECHO && (dst_ip_h & 0xffff0000) != fake_ip4_prefix) {
        return TC_ACT_OK;
      }
    }

    if (IN_LOOPBACK(dst_ip_h) || IN_PRIVATE(dst_ip_h) || IN_MULTICAST(dst_ip_h) || dst_ip_h == INADDR_BROADCAST) {
      return TC_ACT_OK;
    }
  } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end) {
      return TC_ACT_OK;
    }

    if (ip6h->nexthdr == IPPROTO_ICMPV6) {
      struct icmp6hdr *icmp = (struct icmp6hdr *)(ip6h + 1);
      if ((void *)(icmp + 1) > data_end) {
        return TC_ACT_OK;
      }
      if (icmp->icmp6_type == ICMPV6_ECHO_REPLY) {
        return TC_ACT_OK;
      }
      if (icmp->icmp6_type == ICMPV6_ECHO_REQUEST &&
          (ip6h->daddr.in6_u.u6_addr32[0] != fake_ip6_prefix[0] ||
           ip6h->daddr.in6_u.u6_addr32[1] != fake_ip6_prefix[1])) {
        return TC_ACT_OK;
      }
    }

    if (IN6_IS_ADDR_LOOPBACK(&ip6h->daddr)  ||
        IN6_IS_ADDR_LINKLOCAL(&ip6h->daddr) ||
        IN6_IS_ADDR_SITELOCAL(&ip6h->daddr) ||
        IN6_IS_ADDR_MULTICAST(&ip6h->daddr)) {
      return TC_ACT_OK;
    }
  } else {
    return TC_ACT_OK;
  }

  bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), tun_mac, ETH_ALEN, 0);

  return bpf_redirect(tun_ifindex, 0);
}

char _license[] SEC("license") = "GPL";
