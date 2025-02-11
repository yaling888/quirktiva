module quirktiva-test

go 1.24.0

require (
	github.com/docker/docker v27.5.1+incompatible
	github.com/docker/go-connections v0.5.0
	github.com/miekg/dns v1.1.63
	github.com/stretchr/testify v1.10.0
	github.com/yaling888/quirktiva v0.0.0
	go.uber.org/automaxprocs v1.6.0
	golang.org/x/net v0.35.0
)

require (
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/apernet/hysteria/core/v2 v2.5.1-0.20240816231605-7e70547dbdf1 // indirect
	github.com/apernet/hysteria/extras/v2 v2.5.3-0.20241104183808-a2c7b8fd198d // indirect
	github.com/apernet/quic-go v0.48.2-0.20241104191913-cb103fcecfe7 // indirect
	github.com/cilium/ebpf v0.17.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/dlclark/regexp2 v1.11.5 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/expr-lang/expr v1.16.9 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/insomniacslk/dhcp v0.0.0-20250109001534-8abf58130905 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/oschwald/geoip2-golang v1.11.0 // indirect
	github.com/oschwald/maxminddb-golang v1.13.0 // indirect
	github.com/phuslu/log v1.0.113 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/quic-go/quic-go v0.49.0 // indirect
	github.com/samber/lo v1.49.1 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/vishvananda/netlink v1.3.1-0.20250209162617-655392bc778a // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go.etcd.io/bbolt v1.4.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.53.0 // indirect
	go.opentelemetry.io/otel v1.28.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.28.0 // indirect
	go.opentelemetry.io/otel/metric v1.28.0 // indirect
	go.opentelemetry.io/otel/sdk v1.28.0 // indirect
	go.opentelemetry.io/otel/trace v1.28.0 // indirect
	go.starlark.net v0.0.0-20250205221240-492d3672b3f4 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/mock v0.5.0 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.21.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	golang.org/x/time v0.10.0 // indirect
	golang.org/x/tools v0.26.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173 // indirect
	golang.zx2c4.com/wireguard/windows v0.5.4-0.20230123132234-dcc0eb72a04b // indirect
	google.golang.org/protobuf v1.36.5 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gvisor.dev/gvisor v0.0.0-20250210225643-b6c879e0ba3f // indirect
)

replace (
	github.com/apernet/quic-go => github.com/yaling888/quic-hy2 v0.49.0
	github.com/yaling888/quirktiva => ../
)
