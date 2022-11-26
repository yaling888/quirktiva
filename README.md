<h1 align="center">
  <img src="https://github.com/yaling888/clash/raw/plus-pro/docs/logo.png" alt="Clash" width="200">
  <br>Clash<br>
</h1>

<h4 align="center">A rule-based tunnel in Go.</h4>

<p align="center">
  <a href="https://github.com/yaling888/clash/actions">
    <img src="https://img.shields.io/github/workflow/status/yaling888/clash/Go?style=flat-square" alt="Github Actions">
  </a>
  <a href="https://goreportcard.com/report/github.com/yaling888/clash">
    <img src="https://goreportcard.com/badge/github.com/yaling888/clash?style=flat-square">
  </a>
  <img src="https://img.shields.io/github/go-mod/go-version/yaling888/clash?style=flat-square">
  <a href="https://github.com/yaling888/clash/releases">
    <img src="https://img.shields.io/github/release/yaling888/clash/all.svg?style=flat-square">
  </a>
</p>

## Features

- Local HTTP/HTTPS/SOCKS server with authentication support
- Shadowsocks(R), VMess, VLESS, Trojan, Snell, SOCKS5, HTTP(S) outbound support
- Built-in [fake-ip](https://www.rfc-editor.org/rfc/rfc3089) DNS server that aims to minimize DNS pollution attack impact. DoH/DoT upstream supported.
- Rules based off domains, GEOIP, GEOSITE, IP-CIDR or process names to route packets to different destinations
- Proxy groups allow users to implement powerful rules. Supports automatic fallback, load balancing or auto select proxy based off latency
- Remote providers, allowing users to get proxy lists remotely instead of hardcoding in config
- Transparent proxy: Redirect TCP and TProxy TCP/UDP with automatic route table/rule management
- Hot-reload via the comprehensive HTTP RESTful API controller
- System/gVisor stack TUN device on macOS, Linux and Windows
- Policy routing with Scripts

## Getting Started
Documentations are available at [GitHub Wiki](https://github.com/Dreamacro/clash/wiki).

## Advanced usage for this branch
### General configuration
```yaml
sniffing: true # Sniff TLS SNI

force-cert-verify: true # force verify TLS Certificate, prevent machine-in-the-middle attacks

profile:
  tracing: false # prevent logs leak, default value is true
```

### MITM configuration
A root CA certificate is required, the 
MITM proxy server will generate a CA certificate file and a CA private key file in your Clash home directory, you can use your own certificate replace it. 

Need to install and trust the CA certificate on the client device, open this URL [http://mitm.clash/cert.crt](http://mitm.clash/cert.crt) by the web browser to install the CA certificate, the host name 'mitm.clash' was always been hijacked.

NOTE: this feature cannot work on tls pinning

WARNING: DO NOT USE THIS FEATURE TO BREAK LOCAL LAWS

```yaml
# Port of MITM proxy server on the local end
mitm-port: 7894

# Man-In-The-Middle attack
mitm:
  hosts: # use for others proxy type. E.g: TUN, socks
    - +.example.com
  rules: # rewrite rules
    - '^https?://www\.example\.com/1 url reject' # The "reject" returns HTTP status code 404 with no content.
    - '^https?://www\.example\.com/2 url reject-200' # The "reject-200" returns HTTP status code 200 with no content.
    - '^https?://www\.example\.com/3 url reject-img' # The "reject-img" returns HTTP status code 200 with content of 1px png.
    - '^https?://www\.example\.com/4 url reject-dict' # The "reject-dict" returns HTTP status code 200 with content of empty json object.
    - '^https?://www\.example\.com/5 url reject-array' # The "reject-array" returns HTTP status code 200 with content of empty json array.
    - '^https?://www\.example\.com/(6) url 302 https://www.example.com/new-$1'
    - '^https?://www\.(example)\.com/7 url 307 https://www.$1.com/new-7'
    - '^https?://www\.example\.com/8 url request-header (\r\n)User-Agent:.+(\r\n) request-header $1User-Agent: haha-wriohoh$2' # The "request-header" works for all the http headers not just one single header, so you can match two or more headers including CRLF in one regular expression.
    - '^https?://www\.example\.com/9 url request-body "pos_2":\[.*\],"pos_3" request-body "pos_2":[{"xx": "xx"}],"pos_3"'
    - '^https?://www\.example\.com/10 url response-header (\r\n)Tracecode:.+(\r\n) response-header $1Tracecode: 88888888888$2'
    - '^https?://www\.example\.com/11 url response-body "errmsg":"ok" response-body "errmsg":"not-ok"'
```

### DNS configuration
Support resolve ip with a proxy tunnel or interface.

Support `geosite` with `fallback-filter`.

Use `curl -X POST controllerip:port/cache/fakeip/flush` to flush persistence fakeip
 ```yaml
 dns:
   enable: true
   use-hosts: true
   ipv6: false
   enhanced-mode: fake-ip
   fake-ip-range: 198.18.0.1/16
   listen: 127.0.0.1:6868
   default-nameserver:
     - 119.29.29.29
     - 114.114.114.114
   nameserver:
     - https://doh.pub/dns-query
     - tls://223.5.5.5:853
   fallback:
     - 'tls://8.8.4.4:853#proxy or interface'
     - 'https://1.0.0.1/dns-query#Proxy'  # append the proxy adapter name to the end of DNS URL with '#' prefix.
   fallback-filter:
     geoip: false
     geosite:
       - gfw  # `geosite` filter only use fallback server to resolve ip, prevent DNS leaks to untrusted DNS providers.
     domain:
       - +.example.com
     ipcidr:
       - 0.0.0.0/32
 ```

### TUN configuration
Simply add the following to the main configuration:

#### NOTE:
> auto-route and auto-detect-interface only available on macOS, Windows and Linux, receive IPv4 traffic

```yaml
tun:
  enable: true
  stack: system # or gvisor
  # device: tun://utun8 # or fd://xxx, it's optional
  # dns-hijack:
  #   - 8.8.8.8:53
  #   - tcp://8.8.8.8:53
  #   - any:53
  #   - tcp://any:53
  auto-route: true # auto set global route
  auto-detect-interface: true # conflict with interface-name
```
or
```yaml
interface-name: en0

tun:
  enable: true
  stack: system # or gvisor
  # dns-hijack:
  #   - 8.8.8.8:53
  #   - tcp://8.8.8.8:53
  auto-route: true # auto set global route
```
It's recommended to use fake-ip mode for the DNS server.

Clash needs elevated permission to create TUN device:
```sh
$ sudo ./clash
```
Then manually create the default route and DNS server. If your device already has some TUN device, Clash TUN might not work. In this case, fake-ip-filter may helpful.

Enjoy! :)

#### For Windows:
```yaml
tun:
  enable: true
  stack: gvisor # or system
  dns-hijack:
    - 198.18.0.2:53 # when `fake-ip-range` is 198.18.0.1/16, should hijack 198.18.0.2:53
  auto-route: true # auto set global route for Windows
  # It is recommended to use `interface-name`
  auto-detect-interface: true # auto detect interface, conflict with `interface-name`
```
Finally, open the Clash

### Rules configuration
- Support rule `SCRIPT` shortcuts.
- Support rule `GEOSITE`.
- Support rule `USER-AGENT`.
- Support `multiport` condition for rule `SRC-PORT` and `DST-PORT`.

The `GEOIP` databases via [https://github.com/Loyalsoldier/geoip](https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb).

The `GEOSITE` databases via [https://github.com/Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat).
```yaml
mode: rule

script:
  shortcuts: # `src_port` and `dst_port` are number
    quic: 'network == "udp" and dst_port == 443'
    privacy: '"analytics" in host or "adservice" in host or "firebase" in host or "safebrowsing" in host or "doubleclick" in host'
    BilibiliUdp: |
      network == "udp" and match_provider("bilibili")
    ParentalControls: |
      src_ip == "192.168.1.123" and now.hour < 8 and now.hour > 22
rules:
  # rule SCRIPT shortcuts
  - SCRIPT,quic,REJECT # Disable QUIC
  - SCRIPT,privacy,REJECT
  - SCRIPT,BilibiliUdp,REJECT
  - SCRIPT,ParentalControls,REJECT

  # multiport condition for rules SRC-PORT and DST-PORT
  - DST-PORT,123/136/137-139,DIRECT

  # USER-AGENT payload cannot include the comma character, '*' meaning any character.
  - USER-AGENT,*example*,PROXY

  # rule GEOSITE
  - GEOSITE,category-ads-all,REJECT
  - GEOSITE,icloud@cn,DIRECT
  - GEOSITE,apple@cn,DIRECT
  - GEOSITE,apple-cn,DIRECT
  - GEOSITE,microsoft@cn,DIRECT
  - GEOSITE,facebook,PROXY
  - GEOSITE,youtube,PROXY
  - GEOSITE,geolocation-cn,DIRECT
  - GEOSITE,geolocation-!cn,PROXY

  - GEOIP,telegram,PROXY,no-resolve
  - GEOIP,lan,DIRECT,no-resolve
  - GEOIP,cn,DIRECT

  - MATCH,PROXY
```
Script shortcut parameters
```ts
now: {
  year:       int
  month:      int
  day:        int
  hour:       int
  minute:     int
  second:     int
}
type:            string
network:         string
host:            string
process_name:    string
process_path:    string
user_agent:      string
special_proxy:   string
src_ip:          string
src_port:        int
dst_ip:          string // call resolve_ip(host) if empty
dst_port:        int
```
Script shortcut functions
```ts
type resolve_ip = (host: string) => string // ip string
type in_cidr = (ip: string, cidr: string) => boolean // ip in cidr
type geoip = (ip: string) => string // country code
type match_provider = (name: string) => boolean // in rule provider
type resolve_process_name = () => string // process name
type resolve_process_path = () => string // process path
```

### Script configuration
Script enables users to programmatically select a policy for the packets with more flexibility.

NOTE: If you want to use `ctx.geoip(ip)` you need to manually resolve ip first.

```yaml
mode: script

script:
  # path: ./script.star
  code: |
    def main(ctx, metadata):
      processName = ctx.resolve_process_name(metadata)
      if processName == 'apsd':
        return "DIRECT"

      if metadata["network"] == 'udp' and metadata["dst_port"] == 443:
        return "REJECT"

      host = metadata["host"]
      for kw in ['analytics', 'adservice', 'firebase', 'bugly', 'safebrowsing', 'doubleclick']:
        if kw in host:
          return "REJECT"

      # now = time.now()
      # if (now.hour < 8 or now.hour > 18) and metadata["src_ip"] == '192.168.1.99':
      #   return "REJECT"

      if ctx.rule_providers["category-ads-all"].match(metadata):
        return "REJECT"

      if ctx.rule_providers["youtube"].match(metadata):
        ctx.log('[Script] domain %s matched youtube' % host)
        return "Proxy"

      if ctx.rule_providers["geolocation-cn"].match(metadata):
        ctx.log('[Script] domain %s matched geolocation-cn' % host)
        return "DIRECT"

      ip = metadata["dst_ip"]
      if ip == "":
        ip = ctx.resolve_ip(host)
        if ip == "":
          return "Proxy"

      code = ctx.geoip(ip)
      if code == "TELEGRAM":
        ctx.log('[Script] matched telegram')
        return "Proxy"

      if code == "CN" or code == "LAN" or code == "PRIVATE":
        return "DIRECT"

      return "Proxy" # default policy for requests which are not matched by any other script
```
the context and metadata
```ts
interface Metadata {
  type: string // socks5、http
  network: string // tcp、udp
  host: string
  user_agent: string
  special_proxy: string
  src_ip: string
  src_port: string
  dst_ip: string
  dst_port: string
}

interface Context {
  resolve_ip: (host: string) => string // ip string
  resolve_process_name: (metadata: Metadata) => string
  resolve_process_path: (metadata: Metadata) => string
  geoip: (ip: string) => string // country code
  log: (log: string) => void
  proxy_providers: Record<string, Array<{ name: string, alive: boolean, delay: number }>>
  rule_providers: Record<string, { match: (metadata: Metadata) => boolean }>
}
```

### Proxies configuration
Support outbound protocol `VLESS`.

Support `Trojan` with XTLS.

Support userspace `WireGuard` outbound.

Support relay `UDP` traffic.

Support filtering proxy providers in proxy groups.

Support custom http request header, prefix name and V2Ray subscription URL in proxy providers.
```yaml
proxies:
  # VLESS
  - name: "vless-tls"
    type: vless
    server: server
    port: 443
    uuid: uuid
    network: tcp
    servername: example.com
    udp: true
    # skip-cert-verify: true
  - name: "vless-xtls"
    type: vless
    server: server
    port: 443
    uuid: uuid
    network: tcp
    servername: example.com
    flow: xtls-rprx-direct # or xtls-rprx-origin
    # flow-show: true # print the XTLS direction log
    # udp: true
    # skip-cert-verify: true

  # Trojan
  - name: "trojan-xtls"
    type: trojan
    server: server
    port: 443
    password: yourpsk
    network: tcp
    flow: xtls-rprx-direct # or xtls-rprx-origin
    # flow-show: true # print the XTLS direction log
    # udp: true
    # sni: example.com # aka server name
    # skip-cert-verify: true
  
  # WireGuard
  - name: "wg"
    type: wireguard
    server: 127.0.0.1
    port: 443
    ip: 127.0.0.1
    # ipv6: your_ipv6
    private-key: eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=
    public-key: Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=
    # preshared-key: base64
    # dns: [1.1.1.1, 8.8.8.8]
    # mtu: 1420
    udp: true

proxy-groups:
  # Relay chains the proxies. proxies shall not contain a relay.
  # Support relay UDP traffic.
  # Traffic: clash <-> ss1 <-> trojan <-> vmess <-> ss2 <-> Internet
  - name: "relay-udp-over-tcp"
    type: relay
    proxies:
      - ss1
      - trojan
      - vmess
      - ss2

  - name: "relay-raw-udp"
    type: relay
    proxies:
      - ss1
      - ss2
      - ss3
        
  - name: "filtering-proxy-providers"
    type: url-test
    url: "http://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 200
    # lazy: true
    filter: "XXX" # a regular expression
    use:
      - provider1

proxy-providers:
  provider1:
    type: http
    url: "url" # support V2Ray subscription URL
    # url-proxy: true # forward to tun if tun enabled
    interval: 3600
    path: ./providers/provider1.yaml
    # filter: "xxx"
    # prefix-name: "XXX-"
    header:  # custom http request header
      User-Agent:
        - "Clash/v1.10.6"
    #   Accept:
    #     - 'application/vnd.github.v3.raw'
    #   Authorization:
    #     - ' token xxxxxxxxxxx'
    health-check:
      enable: false
      interval: 1200
      # lazy: false # default value is true
      url: http://www.gstatic.com/generate_204
```

### Tunnels configuration
tunnels (like SSH local forwarding).
```yaml
tunnels:
  # one line config
  - tcp/udp,127.0.0.1:6553,114.114.114.114:53,proxy
  - tcp,127.0.0.1:6666,rds.mysql.com:3306,vpn
  # full yaml config
  - network: [tcp, udp]
    address: 127.0.0.1:7777
    target: target.com
    proxy: proxy
```

### eBPF
It requires Linux kernel version >= 4.5, support `redirect-to-tun` and `auto-redir` features.

#### redirect-to-tun:
only hook traffic of the egress NIC, conflict with `auto-route` and `auto-redir`.
```yaml
interface-name: eth0

ebpf:
  redirect-to-tun:
    - eth0

tun:
  enable: true
  stack: system
  dns-hijack:
    - any:53
  auto-route: false
```

#### auto-redir:
only hook TCP traffic of the ingress NIC and conflict with `redirect-to-tun`, It can be replaced with redir-port (TCP) without any network config.

It's recommended to work with TUN to handle UDP traffic. It improves the network throughput performance of some low performance devices compared to using exclusively TUN.
```yaml
interface-name: eth0

ebpf:
  auto-redir:
    - eth0
    # - wlan0

tun:
  enable: true
  stack: system
  dns-hijack:
    - any:53
  auto-route: true
```

### Web GUI
Open the Dashboard online by click [http://yacd.clash-plus.cf](http://yacd.clash-plus.cf) for local API by Safari or [https://yacd.clash-plus.cf](https://yacd.clash-plus.cf) for local API by Chrome.

You can download the [Dashboard](https://github.com/yaling888/yacd/archive/gh-pages.zip) into Clash home directory:
```sh
$ cd ~/.config/clash
$ curl -LJ https://github.com/yaling888/yacd/archive/gh-pages.zip -o yacd-gh-pages.zip
$ unzip yacd-gh-pages.zip
$ mv yacd-gh-pages dashboard
```

Add to config file:
```yaml
external-controller: 127.0.0.1:9090
external-ui: dashboard
```
Open [http://127.0.0.1:9090/ui/](http://127.0.0.1:9090/ui/) by web browser.

## Development
If you want to build an application that uses clash as a library, check out the the [GitHub Wiki](https://github.com/Dreamacro/clash/wiki/use-clash-as-a-library)

## Credits

* [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
* [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
* [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)

## License

This software is released under the GPL-3.0 license.

[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FDreamacro%2Fclash.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FDreamacro%2Fclash?ref=badge_large)
