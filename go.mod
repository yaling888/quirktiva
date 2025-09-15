module github.com/yaling888/quirktiva

go 1.25.0

require (
	github.com/apernet/hysteria/core/v2 v2.6.4
	github.com/apernet/hysteria/extras/v2 v2.6.4
	github.com/cilium/ebpf v0.19.0
	github.com/dlclark/regexp2 v1.11.5
	github.com/expr-lang/expr v1.17.6
	github.com/go-chi/chi/v5 v5.2.3
	github.com/go-chi/cors v1.2.2
	github.com/go-chi/render v1.0.3
	github.com/gorilla/websocket v1.5.3
	github.com/insomniacslk/dhcp v0.0.0-20250828142853-d3abe7ccb0ad
	github.com/miekg/dns v1.1.68
	github.com/oschwald/geoip2-golang v1.13.0
	github.com/phuslu/log v1.0.120
	github.com/quic-go/quic-go v0.54.0
	github.com/samber/lo v1.51.0
	github.com/stretchr/testify v1.11.1
	github.com/vishvananda/netlink v1.3.1
	go.etcd.io/bbolt v1.4.3
	go.starlark.net v0.0.0-20250826212936-2a4f36945129
	go.uber.org/atomic v1.11.0
	go.uber.org/automaxprocs v1.6.0
	golang.org/x/crypto v0.41.1-0.20250904143959-9d779377cff7
	golang.org/x/net v0.43.1-0.20250904165834-b800b2045a8a
	golang.org/x/sync v0.16.1-0.20250813144705-04914c200cb3
	golang.org/x/sys v0.35.1-0.20250904144206-a4712b905411
	golang.org/x/text v0.28.1-0.20250813145300-60c9786d9e6c
	golang.org/x/time v0.12.1-0.20250813144400-c0b0320d156b
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
	golang.zx2c4.com/wireguard/windows v0.5.4-0.20230123132234-dcc0eb72a04b
	google.golang.org/protobuf v1.36.8
	gopkg.in/yaml.v3 v3.0.1
	gvisor.dev/gvisor v0.0.0-20250828211149-1f30edfbb5d4
)

require (
	github.com/ajg/form v1.5.1 // indirect
	github.com/apernet/quic-go v0.54.1-0.20250907230547-eb32f8aec5e2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/oschwald/maxminddb-golang v1.13.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	go.uber.org/mock v0.5.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.26.0 // indirect
	golang.org/x/tools v0.35.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace github.com/apernet/quic-go => github.com/yaling888/quic-hy2 v0.54.0
