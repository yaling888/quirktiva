module github.com/yaling888/quirktiva

go 1.24.1

require (
	github.com/apernet/hysteria/core/v2 v2.6.2
	github.com/apernet/hysteria/extras/v2 v2.6.2
	github.com/cilium/ebpf v0.19.0
	github.com/dlclark/regexp2 v1.11.5
	github.com/expr-lang/expr v1.17.5
	github.com/go-chi/chi/v5 v5.2.2
	github.com/go-chi/cors v1.2.2
	github.com/go-chi/render v1.0.3
	github.com/gorilla/websocket v1.5.3
	github.com/insomniacslk/dhcp v0.0.0-20250417080101-5f8cf70e8c5f
	github.com/miekg/dns v1.1.66
	github.com/oschwald/geoip2-golang v1.13.0
	github.com/phuslu/log v1.0.118
	github.com/quic-go/quic-go v0.53.0
	github.com/samber/lo v1.51.0
	github.com/stretchr/testify v1.10.0
	github.com/vishvananda/netlink v1.3.1
	go.etcd.io/bbolt v1.4.2
	go.starlark.net v0.0.0-20250701195324-d457b4515e0e
	go.uber.org/atomic v1.11.0
	go.uber.org/automaxprocs v1.6.0
	golang.org/x/crypto v0.39.1-0.20250630195050-b3790b8d9143
	golang.org/x/net v0.41.0
	golang.org/x/sync v0.15.1-0.20250620182935-7fad2c9213e0
	golang.org/x/sys v0.33.1-0.20250617173538-751c3c6ac2a6
	golang.org/x/text v0.26.0
	golang.org/x/time v0.12.0
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
	golang.zx2c4.com/wireguard/windows v0.5.4-0.20230123132234-dcc0eb72a04b
	google.golang.org/protobuf v1.36.6
	gopkg.in/yaml.v3 v3.0.1
	gvisor.dev/gvisor v0.0.0-20250708030508-af8a1a4e46f2
)

require (
	github.com/ajg/form v1.5.1 // indirect
	github.com/apernet/quic-go v0.52.1-0.20250607183305-9320c9d14431 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/oschwald/maxminddb-golang v1.13.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	go.uber.org/mock v0.5.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.25.0 // indirect
	golang.org/x/tools v0.33.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace github.com/apernet/quic-go => github.com/yaling888/quic-hy2 v0.52.1
