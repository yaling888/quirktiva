#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include "helper.h"

struct socks_info {
  struct in6_addr addr;
  __be16          port;
  __u16           _pad;
};

struct {
  __uint(type,        BPF_MAP_TYPE_LRU_HASH);
  __type(key,         struct socks_info);
  __type(value,       struct socks_info);
  __uint(max_entries, 65535);
} tcp_map SEC(".maps");

struct {
  __uint(type,        BPF_MAP_TYPE_LRU_HASH);
  __type(key,         struct socks_info);
  __type(value,       struct socks_info);
  __uint(max_entries, 65535);
} udp_map SEC(".maps");

struct context {
  struct in6_addr src_addr;
  struct in6_addr dst_addr;
  struct in6_addr redir_addr;
  __be16          src_port;
  __be16          dst_port;
  __be16          redir_port;
  __u16           _pad;
  __u8            src_mac[ETH_ALEN];
  __u8            dst_mac[ETH_ALEN];
  int             is6;
  int             is_tcp;
  int             is_ping;
  int             connect;
  int             disconnect;
};

const volatile struct in6_addr  redir_ip4;
const volatile struct in6_addr  redir_ip6;
const volatile        __be16    redir_port; // network byte order
const volatile        __u32     fake_ip4_prefix; // host byte order, 16 bits
const volatile        __be32    fake_ip6_prefix[2]; // 64 bits

static __always_inline struct in6_addr ip4_map_6(__be32 *ip) {
  struct in6_addr ip6    = {};
  ip6.in6_u.u6_addr16[5] = bpf_htons(IP4_MAP6_PAD);
  ip6.in6_u.u6_addr32[3] = *ip;
  return ip6;
}

static __always_inline int rewrite_addr(struct __sk_buff *skb, const void *old_ip, const void *new_ip, int is6, int is_tcp, int is_dst) {
  __u32 l3_c_off = 0, l4_c_off = 0, data_off = 0, size = 0, l3_csum = 0;

  if (is6 == 1) {
    size = sizeof(struct in6_addr);
    if (is_tcp == 1) {
      l4_c_off = TCP6_CSUM_OFF;
    } else {
      l4_c_off = UDP6_CSUM_OFF;
    }
    if (is_dst == 1) {
      data_off = IP6_DST_OFF;
    } else {
      data_off = IP6_SRC_OFF;
    }
    l3_csum = bpf_csum_diff((__be32 *)old_ip, size, (__be32 *)new_ip, size, 0);
  } else {
    size = sizeof(__be32);
    l3_c_off = IP_CSUM_OFF;
    if (is_tcp == 1) {
      l4_c_off = TCP_CSUM_OFF;
    } else {
      l4_c_off = UDP_CSUM_OFF;
    }
    if (is_dst == 1) {
      data_off = IP_DST_OFF;
    } else {
      data_off = IP_SRC_OFF;
    }
    l3_csum = bpf_csum_diff(&((struct in6_addr *)old_ip)->in6_u.u6_addr32[3], size, &((struct in6_addr *)new_ip)->in6_u.u6_addr32[3], size, 0);
  }

  int ret = bpf_l4_csum_replace(skb, l4_c_off, 0, l3_csum, BPF_F_PSEUDO_HDR | 0);
  if (ret < 0) {
    return ret;
  }

  if (l3_c_off > 0) {
    ret = bpf_l3_csum_replace(skb, l3_c_off, 0, l3_csum, 0);
    if (ret < 0) {
      return ret;
    }
  }

  if (is6 == 1) {
    ret = bpf_skb_store_bytes(skb, data_off, new_ip, size, 0); // fxxx the BPF_F_RECOMPUTE_CSUM flag
  } else {
    ret = bpf_skb_store_bytes(skb, data_off, &((struct in6_addr *)new_ip)->in6_u.u6_addr32[3], size, 0); // fxxx the BPF_F_RECOMPUTE_CSUM flag
  }
  if (ret < 0) {
    return ret;
  }

  return 1;
}

static __always_inline int rewrite_port(struct __sk_buff *skb, __be16 old_port, __be16 new_port, int is6, int is_tcp, int is_dst) {
  __u32 l4_c_off = 0, data_off = 0;

  if (is6 == 1) {
    if (is_tcp == 1) {
      l4_c_off = TCP6_CSUM_OFF;
      if (is_dst == 1) {
        data_off = TCP6_DST_OFF;
      } else {
        data_off = TCP6_SRC_OFF;
      }
    } else {
      l4_c_off = UDP6_CSUM_OFF;
      if (is_dst == 1) {
        data_off = UDP6_DST_OFF;
      } else {
        data_off = UDP6_SRC_OFF;
      }
    }
  } else {
    if (is_tcp == 1) {
      l4_c_off = TCP_CSUM_OFF;
      if (is_dst == 1) {
        data_off = TCP_DST_OFF;
      } else {
        data_off = TCP_SRC_OFF;
      }
    } else {
      l4_c_off = UDP_CSUM_OFF;
      if (is_dst == 1) {
        data_off = UDP_DST_OFF;
      } else {
        data_off = UDP_SRC_OFF;
      }
    }
  }

  int ret = bpf_l4_csum_replace(skb, l4_c_off, old_port, new_port, sizeof(new_port));
  if (ret < 0) {
    return ret;
  }

  ret = bpf_skb_store_bytes(skb, data_off, &new_port, sizeof(new_port), 0); // fxxx the BPF_F_RECOMPUTE_CSUM flag
  if (ret < 0) {
    return ret;
  }

  return 1;
}

static __always_inline int handle_ping4(struct __sk_buff *skb, struct context *ctx) {
  bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), ctx->dst_mac, ETH_ALEN, 0);
  bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), ctx->src_mac, ETH_ALEN, 0);

  bpf_skb_store_bytes(skb, IP_SRC_OFF, &ctx->dst_addr.in6_u.u6_addr32[3], sizeof(ctx->dst_addr.in6_u.u6_addr32[3]), 0);
  bpf_skb_store_bytes(skb, IP_DST_OFF, &ctx->src_addr.in6_u.u6_addr32[3], sizeof(ctx->src_addr.in6_u.u6_addr32[3]), 0);

  __u8 new_type = 0; // ICMP_ECHOREPLY
  bpf_l4_csum_replace(skb, ICMP_CSUM_OFF, ICMP_ECHO, new_type, sizeof(__u16));
	bpf_skb_store_bytes(skb, ICMP_TYPE_OFF, &new_type, sizeof(new_type), 0);

	bpf_clone_redirect(skb, skb->ifindex, 0);

	return TC_ACT_SHOT;
}

static __always_inline int handle_ping6(struct __sk_buff *skb, struct context *ctx) {
  bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), ctx->dst_mac, ETH_ALEN, 0);
  bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), ctx->src_mac, ETH_ALEN, 0);

  bpf_skb_store_bytes(skb, IP6_SRC_OFF, &ctx->dst_addr, sizeof(ctx->dst_addr), 0);
  bpf_skb_store_bytes(skb, IP6_DST_OFF, &ctx->src_addr, sizeof(ctx->src_addr), 0);

  __u8 new_type = 129; // ICMPV6_ECHO_REPLY
  bpf_l4_csum_replace(skb, ICMP6_CSUM_OFF, ICMPV6_ECHO_REQUEST, new_type, sizeof(__u16));
	bpf_skb_store_bytes(skb, ICMP6_TYPE_OFF, &new_type, sizeof(new_type), 0);

	bpf_clone_redirect(skb, skb->ifindex, 0);

  return TC_ACT_SHOT;
}

static int extract_context_from_skb(struct __sk_buff *skb, struct context *ctx) {
  void *data          = (void *)(long)skb->data;
  void *data_end      = (void *)(long)skb->data_end;
  struct ethhdr *eth  = data;

  if ((void *)(eth + 1) > data_end) {
    return -1;
  }

  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
      return -1;
    }

    __builtin_memset(ctx, 0, sizeof(*ctx));

    if (iph->protocol == IPPROTO_TCP) {
      struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
      if ((void *)(tcph + 1) > data_end) {
        return -1;
      }
      ctx->src_port   = tcph->source;
      ctx->dst_port   = tcph->dest;
      ctx->connect    = tcph->syn && !tcph->ack ? 1 : 0;
      ctx->disconnect = tcph->fin && tcph->ack ? 1 : 0;
      ctx->is_tcp     = 1;
    } else if (iph->protocol == IPPROTO_UDP) {
      struct udphdr *udph = (struct udphdr *)(iph + 1);
      if ((void *)(udph + 1) > data_end) {
        return -1;
      }
      ctx->src_port = udph->source;
      ctx->dst_port = udph->dest;
    } else if (iph->protocol == IPPROTO_ICMP) {
      struct icmphdr *icmp = (struct icmphdr *)(iph + 1);
      if ((void *)(icmp + 1) > data_end) {
        return -1;
      }
      if (icmp->type != ICMP_ECHO) {
        return -1;
      }
      __builtin_memcpy(ctx->src_mac, eth->h_source, ETH_ALEN);
      __builtin_memcpy(ctx->dst_mac, eth->h_dest, ETH_ALEN);
      ctx->is_ping = 1;
    } else {
      return -1;
    }

    ctx->src_addr   = ip4_map_6(&iph->saddr);
    ctx->dst_addr   = ip4_map_6(&iph->daddr);
    ctx->redir_addr = redir_ip4;
    ctx->redir_port = redir_port;

    return 1;
  }

  if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end) {
      return -1;
    }

    __builtin_memset(ctx, 0, sizeof(*ctx));

    if (ip6h->nexthdr == IPPROTO_TCP) {
      struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1);
      if ((void *)(tcph + 1) > data_end) {
        return -1;
      }
      ctx->src_port   = tcph->source;
      ctx->dst_port   = tcph->dest;
      ctx->connect    = tcph->syn && !tcph->ack ? 1 : 0;
      ctx->disconnect = tcph->fin && tcph->ack ? 1 : 0;
      ctx->is_tcp     = 1;
    } else if (ip6h->nexthdr == IPPROTO_UDP) {
      struct udphdr *udph = (struct udphdr *)(ip6h + 1);
      if ((void *)(udph + 1) > data_end) {
        return -1;
      }
      ctx->src_port = udph->source;
      ctx->dst_port = udph->dest;
    } else if (ip6h->nexthdr == IPPROTO_ICMPV6) {
      struct icmp6hdr *icmp = (struct icmp6hdr *)(ip6h + 1);
      if ((void *)(icmp + 1) > data_end) {
        return -1;
      }
      if (icmp->icmp6_type != ICMPV6_ECHO_REQUEST) {
        return -1;
      }
      __builtin_memcpy(ctx->src_mac, eth->h_source, ETH_ALEN);
      __builtin_memcpy(ctx->dst_mac, eth->h_dest, ETH_ALEN);
      ctx->is_ping = 1;
    } else {
      return -1;
    }

    ctx->src_addr   = ip6h->saddr;
    ctx->dst_addr   = ip6h->daddr;
    ctx->redir_addr = redir_ip6;
    ctx->redir_port = redir_port;
    ctx->is6        = 1;

    return 1;
  }

  return -1;
}

SEC("tc_clash_auto_redir_ingress")
int tc_redir_ingress_func(struct __sk_buff *skb) {
  struct context ctx = {};

  if (extract_context_from_skb(skb, &ctx) < 0) {
    return TC_ACT_OK;
  }

  if (IN6_ARE_ADDR_EQUAL(&ctx.dst_addr, &ctx.redir_addr)) {
    return TC_ACT_OK;
  }

  if (ctx.is6 == 1) {
    if (IN6_IS_ADDR_LOOPBACK(&ctx.dst_addr)   ||
        IN6_IS_ADDR_LINKLOCAL(&ctx.dst_addr)  ||
        IN6_IS_ADDR_SITELOCAL(&ctx.dst_addr)  ||
        IN6_IS_ADDR_MULTICAST(&ctx.dst_addr)) {
      return TC_ACT_OK;
    }

    if (ctx.is_ping == 1) {
      if (ctx.dst_addr.in6_u.u6_addr32[0] != fake_ip6_prefix[0] || ctx.dst_addr.in6_u.u6_addr32[1] != fake_ip6_prefix[1]) {
        return TC_ACT_OK;
      }
      return handle_ping6(skb, &ctx);
    }
  } else {
    __u32 dst_ip_h = bpf_ntohl(ctx.dst_addr.in6_u.u6_addr32[3]);
    if (IN_LOOPBACK(dst_ip_h) || IN_PRIVATE(dst_ip_h) || IN_MULTICAST(dst_ip_h) || dst_ip_h == INADDR_BROADCAST) {
      return TC_ACT_OK;
    }

    if (ctx.is_ping == 1) {
      if ((dst_ip_h & 0xffff0000) != fake_ip4_prefix) {
        return TC_ACT_OK;
      }
      return handle_ping4(skb, &ctx);
    }
  }

  struct socks_info key = {};
  key.addr = ctx.src_addr;
  key.port = ctx.src_port;

  if (ctx.is_tcp == 1) {
    if (ctx.connect == 1) {
      struct socks_info value = {};
      value.addr = ctx.dst_addr;
      value.port = ctx.dst_port;

      bpf_map_update_elem(&tcp_map, &key, &value, BPF_ANY);

    } else if (!bpf_map_lookup_elem(&tcp_map, &key)) {
      return TC_ACT_OK;
    }
  } else {
    struct socks_info value = {};
    value.addr = ctx.dst_addr;
    value.port = ctx.dst_port;

    bpf_map_update_elem(&udp_map, &key, &value, BPF_ANY);

    if (ctx.dst_port == bpf_htons(53)) { // hijack udp dns packet, ensure your dns server listen on address [::]:53
      if (rewrite_addr(skb, &ctx.dst_addr, &ctx.redir_addr, ctx.is6, ctx.is_tcp, 1) < 0) {
        return TC_ACT_SHOT;
      }
      return TC_ACT_OK;
    }
  }

  if (rewrite_addr(skb, &ctx.dst_addr, &ctx.redir_addr, ctx.is6, ctx.is_tcp, 1) < 0) {
    return TC_ACT_SHOT;
  }

  if (rewrite_port(skb, ctx.dst_port, ctx.redir_port, ctx.is6, ctx.is_tcp, 1) < 0) {
    return TC_ACT_SHOT;
  }

  return TC_ACT_OK;
}

SEC("tc_clash_auto_redir_egress")
int tc_redir_egress_func(struct __sk_buff *skb) {
  struct context ctx = {};

  if (extract_context_from_skb(skb, &ctx) < 0) {
    return TC_ACT_OK;
  }

  if (!IN6_ARE_ADDR_EQUAL(&ctx.src_addr, &ctx.redir_addr)) {
    return TC_ACT_OK;
  }

  struct socks_info key = {}, *value = NULL;
  key.addr = ctx.dst_addr;
  key.port = ctx.dst_port;

  if (ctx.is_tcp == 1) {
    if (ctx.src_port != ctx.redir_port) {
      return TC_ACT_OK;
    }

    value = bpf_map_lookup_elem(&tcp_map, &key);
    if (!value) {
      return TC_ACT_OK;
    }

    if (ctx.disconnect == 1) {
      bpf_map_delete_elem(&tcp_map, &key);
    }
  } else {
    if (ctx.src_port != ctx.redir_port && ctx.src_port != bpf_htons(53)) {
      return TC_ACT_OK;
    }

    value = bpf_map_lookup_elem(&udp_map, &key);
    if (!value) {
      return TC_ACT_OK;
    }

    if (ctx.src_port == value->port) { // restore udp dns packet source address
      if (IN6_ARE_ADDR_EQUAL(&ctx.src_addr, &value->addr)) {
        return TC_ACT_OK;
      }
      if (rewrite_addr(skb, &ctx.src_addr, &value->addr, ctx.is6, ctx.is_tcp, -1) < 0) {
        return TC_ACT_SHOT;
      }
      return TC_ACT_OK;
    }
  }

  if (rewrite_addr(skb, &ctx.src_addr, &value->addr, ctx.is6, ctx.is_tcp, 0) < 0) {
    return TC_ACT_SHOT;
  }

  if (rewrite_port(skb, ctx.src_port, value->port, ctx.is6, ctx.is_tcp, 0) < 0) {
    return TC_ACT_SHOT;
  }

  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
