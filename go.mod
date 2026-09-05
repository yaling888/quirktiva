module github.com/yaling888/quirktiva

go 1.27.1

require (
	github.com/andybalholm/brotli v1.2.3
	github.com/apernet/hysteria/core/v2 v2.12.2
	github.com/apernet/hysteria/extras/v2 v2.12.2
	github.com/cilium/ebpf v0.22.0
	github.com/dlclark/regexp2/v2 v2.7.2
	github.com/expr-lang/expr v1.17.8
	github.com/go-chi/chi/v5 v5.3.2
	github.com/go-chi/cors v1.2.2
	github.com/go-chi/render v1.0.3
	github.com/gorilla/websocket v1.5.3
	github.com/insomniacslk/dhcp v0.0.0-20260901064844-234b97448fae
	github.com/klauspost/compress v1.20.0
	github.com/miekg/dns v1.1.73
	github.com/oschwald/geoip2-golang/v2 v2.3.0
	github.com/phuslu/log v1.0.128
	github.com/quic-go/quic-go v0.62.0
	github.com/refraction-networking/utls v1.8.3-0.20260301010127-aa6edf4b11af
	github.com/sagernet/sing v0.9.2
	github.com/samber/lo v1.53.0
	github.com/stretchr/testify v1.12.1
	github.com/vishvananda/netlink v1.3.1
	go.etcd.io/bbolt v1.5.0
	go.starlark.net v0.0.0-20260904161901-6ecada49e42f
	go.uber.org/atomic v1.11.0
	go.uber.org/automaxprocs v1.6.0
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/crypto v0.56.0
	golang.org/x/net v0.58.1-0.20260904215552-c23af1b9b8cc
	golang.org/x/sync v0.22.1-0.20260831030441-f75267d8412f
	golang.org/x/sys v0.47.1-0.20260831194343-613e2570718e
	golang.org/x/text v0.41.1-0.20260828012921-f53c31601f90
	golang.org/x/time v0.15.1-0.20260819171618-fb013b3d305a
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
	golang.zx2c4.com/wireguard/windows v0.5.4-0.20230123132234-dcc0eb72a04b
	google.golang.org/protobuf v1.36.12
	gvisor.dev/gvisor v0.0.0-20260906120324-45bde0d1defa
)

require (
	github.com/ajg/form v1.5.1 // indirect
	github.com/apernet/quic-go v0.61.1-0.20260806010916-184d081eef3e // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/oschwald/maxminddb-golang/v2 v2.5.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/stretchr/objx v0.5.3 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/exp v0.0.0-20260820142414-ca536658362e // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace github.com/apernet/quic-go => github.com/yaling888/quic-hy2 v0.62.0
