<h1 align="center">
  <img src="https://github.com/yaling888/quirktiva/raw/plus/docs/logo.png" alt="Quirktiva" width="200">
  <br>Quirktiva<br>
</h1>

<h4 align="center">A rule-based tunnel in Go.</h4>

<p align="center">
  <a href="https://github.com/yaling888/quirktiva/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/yaling888/quirktiva/release.yml?branch=plus&style=flat-square" alt="Github Actions">
  </a>
  <a href="https://goreportcard.com/report/github.com/yaling888/quirktiva">
    <img src="https://goreportcard.com/badge/github.com/yaling888/quirktiva?style=flat-square">
  </a>
  <img src="https://img.shields.io/github/go-mod/go-version/yaling888/quirktiva/plus?style=flat-square">
  <a href="https://github.com/yaling888/quirktiva/releases">
    <img src="https://img.shields.io/github/release/yaling888/quirktiva/all.svg?style=flat-square">
  </a>
</p>

## Features

- Local HTTP/HTTPS/SOCKS server with authentication support
- Shadowsocks(R), VMess, VLESS, Trojan, Snell, WireGuard, Hysteria2, SOCKS5, HTTP(S) outbound support
- Built-in [fake-ip](https://www.rfc-editor.org/rfc/rfc3089) DNS server that aims to minimize DNS pollution attack impact. DoH/DoT upstream supported.
- Rules based off dynamic scripting, domains, GEOIP, GEOSITE, IP-CIDR or process names to route packets to different destinations
- Proxy groups allow users to implement powerful rules. Supports automatic fallback, load balancing or auto select proxy based off latency
- Remote providers, allowing users to get proxy lists remotely instead of hardcoding in config
- Transparent proxy: Redirect TCP and TProxy TCP/UDP with automatic route table/rule management
- Hot-reload via the comprehensive HTTP RESTful API controller
- System/gVisor stack TUN device on macOS, Linux and Windows
- Policy routing with Scripts

## Getting Started
Documentations are available at [GitHub Wiki](https://yaling888.github.io/quirktiva/).

## Advanced usage for this branch
### General configuration
```yaml
# sniffing: true # Sniff TLS SNI

force-cert-verify: true # force verify TLS Certificate for all proxies, prevent Machine-In-The-Middle attack

profile:
  tracing: false # prevent logs leak, default value is true

experimental:
  udp-fallback-policy: 'a proxy that supports UDP' # or `direct` or `reject`
```

### MITM configuration
A root CA certificate is required, the 
MITM proxy server will generate a CA certificate file and a CA private key file in your Clash home directory, you can use your own certificate replace it. 

Need to install and trust the CA certificate on the client device, open this URL [http://mitm.clash/cert.crt](http://mitm.clash/cert.crt) by the web browser to install the CA certificate, the host name 'mitm.clash' was always been hijacked.

NOTE: this feature cannot work on tls pinning

```yaml
# Port of MITM proxy server on the local end
mitm-port: 7894

# Machine-In-The-Middle attack
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
Support lookup ip with a proxy tunnel or interface.

Support `geosite` with `fallback-filter`.

Use `curl -X POST controllerip:port/cache/fakeip/flush` to flush persistence fakeip
 ```yaml
 dns:
   enable: true
   use-hosts: true
   ipv6: false
   remote-dns-resolve: true # remote resolve DNS on handle TCP connect and UDP session, default value is true
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
     - 'https://1.0.0.1/dns-query#Proxy' # use a proxy or interface
   remote-nameserver: # remote resolve DNS
     - 'tls://1.1.1.1:853'
     - 'tls://8.8.8.8:853'
   fallback-filter:
     geoip: false
     geosite:
       - gfw  # `geosite` filter only use fallback server to lookup ip, prevent DNS leaks to untrusted DNS providers.
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

Quirktiva needs elevated permission to create TUN device:
```sh
$ sudo ./quirktiva
```
Then manually create the default route and DNS server. If your device already has some TUN device, Quirktiva TUN might not work. In this case, fake-ip-filter may helpful.

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
Finally, open the Quirktiva

### Rules configuration
- Support rule `SCRIPT` shortcuts.
- Support rule `GEOSITE`.
- Support rule `USER-AGENT`.
- Support `multiport` condition for rule `SRC-PORT` and `DST-PORT`.
- Support nestable "rule groups", `if` field is the same as the shortcut syntax and if none of the sub-rules match, then continue to match the next rule.

Script shortcuts engines: [expr](https://expr-lang.org/) & [starlark](https://github.com/google/starlark-go).

```yaml
mode: rule

script:
  engine: expr # or starlark (10x to 20x slower), the default engine is `expr`
  shortcuts: # `src_port` and `dst_port` are number
    quic: 'network == "udp" and dst_port == 443'
    # privacy: '"analytics" in host or "adservice" in host or "firebase" in host or "safebrowsing" in host or "doubleclick" in host'
    privacy: |
      any(["analytics", "adservice", "firebase", "safebrowsing", "doubleclick", "bugly", "bugsnag"], host contains #)
    BilibiliUdp: |
      network == "udp" and match_provider("bilibili")
    ParentalControls: |
      src_ip == "192.168.1.123" and now.hour < 8 and now.hour > 22
rules:
  - if: network == 'tcp'
    name: TCP
    # engine: expr # the default engine is `expr`, `starlark` is also valid
    rules:
      - if: dst_port == 443
        name: HTTPS
        rules:
          - MATCH,DIRECT
      - DOMAIN-SUFFIX,baidu.com,DIRECT

  # rule SCRIPT shortcuts
  - SCRIPT,quic,REJECT # Disable QUIC
  - SCRIPT,privacy,REJECT
  - SCRIPT,BilibiliUdp,REJECT
  - SCRIPT,ParentalControls,REJECT

  # multiport condition for rules SRC-PORT and DST-PORT
  - DST-PORT,123/136/137-139,DIRECT,udp

  # USER-AGENT payload cannot include the comma character, '*' meaning any character.
  # - USER-AGENT,*example*,PROXY

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
src_port:        uint16
dst_ip:          string // call resolve_ip(host) if empty
dst_port:        uint16
inbound_port:    uint16
```
Script shortcut functions
```ts
type resolve_ip = (host: string) => string // ip string
type in_cidr = (ip: string, cidr: string) => boolean // ip in cidr
type in_ipset = (name: string, ip: string) => boolean // ip in ipset
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

      if metadata["network"] == 'udp' and metadata["dst_port"] == '443':
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
  inbound_port: number
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

Support outbound protocol `Hysteria2`.

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
    # remote-dns-resolve: true # remote resolve DNS with `dns` field, default is true
    # dns: [1.1.1.1, 8.8.8.8]
    # mtu: 1420
    udp: true

  # Hysteria2
  - name: "hysteria"
    type: hysteria2
    server: server
    port: 443
    password: password
    sni: sni
    # skip-cert-verify: false
    # pin-sha256: pinSha256
    # up: 100 # default unit is Mbps
    # down: 1000 # default unit is Mbps, E.g. "100 Mbps", "512 kbps", "1g" are all valid.
    # obfs: plain # or salamander
    # obfs-param: salamander-password
    # udp: true

  # Trojan QUIC
  - name: "trojan-quic"
    type: trojan
    server: server
    port: 443
    password: password
    udp: true
    alpn:
      - h3
    sni: example.com
    network: quic
    quic-opts:
      cipher: none # aes-128-gcm / chacha20-poly1305
      key: your_key
      obfs: none # srtp / utp / dtls / wechat-video / wireguard

  # VMess QUIC
  - name: "vmess-quic"
    type: vmess
    server: server
    port: 443
    uuid: uuid
    alterId: 0
    cipher: auto
    udp: true
    tls: true
    alpn:
      - h3
    servername: example.com
    network: quic
    quic-opts:
      cipher: none # aes-128-gcm / chacha20-poly1305
      key: your_key
      obfs: none # srtp / utp / dtls / wechat-video / wireguard

proxy-groups:
  # Relay chains the proxies. proxies shall not contain a relay.
  # Support relay UDP traffic.
  # Traffic: quirktiva <-> ss1 <-> trojan <-> vmess <-> ss2 <-> Internet
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
    interval: 5m # support human-friendly config (30s 1h 10m30s etc.)
    tolerance: 200ms # support human-friendly config (30s 1h 10m30s etc.)
    # lazy: true
    # disable-dns: true # disable remote resolve DNS for this group
    filter: "XXX" # a regular expression
    use:
      - provider1

proxy-providers:
  provider1:
    type: http
    url: "url"
    interval: 24h # support human-friendly config (30s 1h 10m30s etc.)
    path: ./providers/provider1.yaml
    # prefix-name: "XXX-" # append a prefix name to each proxy name to avoid duplicate names with other proxies
    # url-proxy: true # proxy the URL by inbounds or TUN
    # rand-host: true # use a random host for http/ws network, it will overwrite the `host` field in http-opts and ws-opts
    # disable-dns: true # disable remote resolve DNS
    # udp: true # force enable UDP traffic, it will overwrite the `udp` field, conflict with `disable-udp` field
    # disable-udp: true # disable UDP traffic, it will overwrite the `udp` field
    force-cert-verify: true # force verify TLS Certificate, default value is true, if the value is true then overwrite the `skip-cert-verify` value to false
    # header:  # custom http request header
      # User-Agent:
      #   - "Clash/v1.18.0"
      # Accept:
      #   - 'application/vnd.github.v3.raw'
      # Authorization:
      #   - ' token xxxxxxxxxxx'
    health-check:
      enable: false
      interval: 0
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

### Template
* [General](https://github.com/yaling888/quirktiva/blob/plus/examples/template/local-client.yaml), usually used as a local client.
* [Auto redirect](https://github.com/yaling888/quirktiva/blob/plus/examples/template/auto-redir-transparent-gateway.yaml), usually used as a transparent proxy gateway.
* [Redirect to tun](https://github.com/yaling888/quirktiva/blob/plus/examples/template/redirect-to-tun-transparent-gateway.yaml), usually used as a transparent proxy gateway.

### Daemon
* For [macOS](https://github.com/yaling888/quirktiva/blob/plus/examples/daemon/macos/org.eu.clashplus.plist).
* For [Linux](https://github.com/yaling888/quirktiva/blob/plus/examples/daemon/linux/clash.service).
* For [Windows](https://github.com/yaling888/SoulX).

### Web GUI
Open the Dashboard online by click [http://yacd.eu.org](http://yacd.eu.org) for local API by Safari or [https://yacd.eu.org](https://yacd.eu.org) for local API by Chrome.

You can download the [Dashboard](https://github.com/yaling888/yacd/archive/gh-pages.zip) into Clash home directory:
```sh
mkdir -p ~/.config/clash && \
cd ~/.config/clash && \
curl -LJ https://github.com/yaling888/yacd/archive/gh-pages.zip -o yacd-gh-pages.zip && \
unzip yacd-gh-pages.zip && \
rm -rf dashboard/ yacd-gh-pages.zip && \
mv yacd-gh-pages dashboard
```

Add to config file:
```yaml
external-controller: 127.0.0.1:9090
external-ui: dashboard
```
Open [http://127.0.0.1:9090/ui/](http://127.0.0.1:9090/ui/) by web browser.

### Set up a free tunnel server on Cloudflare Workers
**NOTE**: The Cloudflare Workers outbound TCP sockets to [Cloudflare IP ranges](https://www.cloudflare.com/ips/) are temporarily blocked and the outbound UDP is not supported.

1. Create a Cloudflare Worker application.
2. Set up a custom domain for your Worker application.
3. Check the repository [Trovle](https://github.com/yaling888/trovle), the transport `Trojan` and `VLESS` are supported.
4. Copy [worker.js](https://github.com/yaling888/trovle/blob/main/worker.js) content into your Worker application.
5. Edit the `configs`, modify the uuid and password.
6. Save and deploy.

## Credits

* [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
* [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
* [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)
