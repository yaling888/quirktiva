module github.com/yaling888/quirktiva

go 1.26.1

require (
	github.com/andybalholm/brotli v1.2.0
	github.com/apernet/hysteria/core/v2 v2.7.1
	github.com/apernet/hysteria/extras/v2 v2.7.1
	github.com/cilium/ebpf v0.21.0
	github.com/dlclark/regexp2 v1.11.5
	github.com/expr-lang/expr v1.17.8
	github.com/go-chi/chi/v5 v5.2.5
	github.com/go-chi/cors v1.2.2
	github.com/go-chi/render v1.0.3
	github.com/gorilla/websocket v1.5.3
	github.com/insomniacslk/dhcp v0.0.0-20260220084031-5adc3eb26f91
	github.com/klauspost/compress v1.18.4
	github.com/miekg/dns v1.1.72
	github.com/oschwald/geoip2-golang/v2 v2.1.0
	github.com/phuslu/log v1.0.121
	github.com/quic-go/quic-go v0.59.0
	github.com/samber/lo v1.53.0
	github.com/stretchr/testify v1.11.1
	github.com/vishvananda/netlink v1.3.1
	go.etcd.io/bbolt v1.4.3
	go.starlark.net v0.0.0-20260210143700-b62fd896b91b
	go.uber.org/atomic v1.11.0
	go.uber.org/automaxprocs v1.6.0
	golang.org/x/crypto v0.48.1-0.20260213171211-a408498e5541
	golang.org/x/net v0.51.1-0.20260306001129-8afa12f92739
	golang.org/x/sync v0.19.1-0.20260223185442-ec11c4a93de2
	golang.org/x/sys v0.41.1-0.20260303015103-eaaaaee1dc1a
	golang.org/x/text v0.34.1-0.20260211190941-73d1ba91404d
	golang.org/x/time v0.14.1-0.20260211191429-812b343c8714
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
	golang.zx2c4.com/wireguard/windows v0.5.4-0.20230123132234-dcc0eb72a04b
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
	gvisor.dev/gvisor v0.0.0-20260212224830-e5b717ac263e
)

require (
	github.com/ajg/form v1.5.1 // indirect
	github.com/apernet/quic-go v0.59.1-0.20260217092621-db4786c77a22 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/oschwald/maxminddb-golang/v2 v2.1.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.32.0 // indirect
	golang.org/x/tools v0.41.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace github.com/apernet/quic-go => github.com/yaling888/quic-hy2 v0.59.100
