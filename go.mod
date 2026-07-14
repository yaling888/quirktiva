module github.com/yaling888/quirktiva

go 1.26.5

require (
	github.com/andybalholm/brotli v1.2.2
	github.com/apernet/hysteria/core/v2 v2.10.0
	github.com/apernet/hysteria/extras/v2 v2.10.0
	github.com/cilium/ebpf v0.22.0
	github.com/dlclark/regexp2/v2 v2.5.0
	github.com/expr-lang/expr v1.17.8
	github.com/go-chi/chi/v5 v5.3.1
	github.com/go-chi/cors v1.2.2
	github.com/go-chi/render v1.0.3
	github.com/gorilla/websocket v1.5.3
	github.com/insomniacslk/dhcp v0.0.0-20260603135910-a415979eb11e
	github.com/klauspost/compress v1.19.0
	github.com/miekg/dns v1.1.72
	github.com/oschwald/geoip2-golang/v2 v2.2.0
	github.com/phuslu/log v1.0.127
	github.com/quic-go/quic-go v0.60.0
	github.com/sagernet/sing v0.8.10
	github.com/samber/lo v1.53.0
	github.com/stretchr/testify v1.11.1
	github.com/vishvananda/netlink v1.3.1
	go.etcd.io/bbolt v1.5.0
	go.starlark.net v0.0.0-20260710210843-dbae659a796e
	go.uber.org/atomic v1.11.0
	go.uber.org/automaxprocs v1.6.0
	golang.org/x/crypto v0.54.0
	golang.org/x/net v0.57.0
	golang.org/x/sync v0.22.0
	golang.org/x/sys v0.47.0
	golang.org/x/text v0.40.0
	golang.org/x/time v0.15.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
	golang.zx2c4.com/wireguard/windows v0.5.4-0.20230123132234-dcc0eb72a04b
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
	gvisor.dev/gvisor v0.0.0-20260715073107-67db8f16ca32
)

require (
	github.com/ajg/form v1.5.1 // indirect
	github.com/apernet/quic-go v0.60.1-0.20260618182935-599b15a1fa26 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/oschwald/maxminddb-golang/v2 v2.3.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace github.com/apernet/quic-go => github.com/yaling888/quic-hy2 v0.60.0
