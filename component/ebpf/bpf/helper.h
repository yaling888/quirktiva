#ifndef _NETINET_IN_H
# undef   __GNUC__
# include <netinet/in.h>
#endif

#ifndef IN_LOOPBACK
# define IN_LOOPBACK(a)         ((((in_addr_t)(a)) & 0xff000000) == 0x7f000000)
#endif

#ifndef IN_PRIVATE
# define IN_PRIVATE(a)          (((((in_addr_t)(a)) & 0xff000000) == 0x0a000000) || \
                                 ((((in_addr_t)(a)) & 0xfff00000) == 0xac100000) || \
                                 ((((in_addr_t)(a)) & 0xffff0000) == 0xc0a80000))
#endif

#define IP4_MAP6_PAD            0xffff

#define IP_CSUM_OFF     (ETH_HLEN + offsetof(struct iphdr, check))

#define IP_DST_OFF      (ETH_HLEN + offsetof(struct iphdr, daddr))

#define IP_SRC_OFF      (ETH_HLEN + offsetof(struct iphdr, saddr))

#define TCP_CSUM_OFF    (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))

#define TCP_SRC_OFF     (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))

#define TCP_DST_OFF     (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))

#define UDP_CSUM_OFF    (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))

#define UDP_SRC_OFF     (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source))

#define UDP_DST_OFF     (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest))

#define ICMP_CSUM_OFF   (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))

#define ICMP_TYPE_OFF   (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))

#define IP6_DST_OFF     (ETH_HLEN + offsetof(struct ipv6hdr, daddr))

#define IP6_SRC_OFF     (ETH_HLEN + offsetof(struct ipv6hdr, saddr))

#define TCP6_CSUM_OFF   (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check))

#define TCP6_SRC_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, source))

#define TCP6_DST_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, dest))

#define UDP6_CSUM_OFF   (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, check))

#define UDP6_SRC_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, source))

#define UDP6_DST_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, dest))

#define ICMP6_CSUM_OFF  (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct icmp6hdr, icmp6_cksum))

#define ICMP6_TYPE_OFF  (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct icmp6hdr, icmp6_type))
