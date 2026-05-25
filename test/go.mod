module quirktiva-test

go 1.26.3

require (
	github.com/miekg/dns v1.1.72
	github.com/moby/moby/api v1.54.2
	github.com/moby/moby/client v0.4.1
	github.com/stretchr/testify v1.11.1
	github.com/yaling888/quirktiva v0.0.0
	go.uber.org/automaxprocs v1.6.0
	golang.org/x/net v0.55.0
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/andybalholm/brotli v1.2.1 // indirect
	github.com/apernet/hysteria/core/v2 v2.9.2 // indirect
	github.com/apernet/hysteria/extras/v2 v2.9.2 // indirect
	github.com/apernet/quic-go v0.59.1-0.20260425001925-6c6cc9bcb716 // indirect
	github.com/cilium/ebpf v0.21.0 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/dlclark/regexp2/v2 v2.1.0 // indirect
	github.com/docker/go-connections v0.7.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/expr-lang/expr v1.17.8 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/insomniacslk/dhcp v0.0.0-20260407060928-11b94ed970f2 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/oschwald/geoip2-golang/v2 v2.1.0 // indirect
	github.com/oschwald/maxminddb-golang/v2 v2.1.1 // indirect
	github.com/phuslu/log v1.0.124 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.59.0 // indirect
	github.com/samber/lo v1.53.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	go.etcd.io/bbolt v1.4.3 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel v1.36.0 // indirect
	go.opentelemetry.io/otel/metric v1.36.0 // indirect
	go.opentelemetry.io/otel/trace v1.36.0 // indirect
	go.starlark.net v0.0.0-20260326113308-fadfc96def35 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/goleak v1.3.0 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446 // indirect
	golang.zx2c4.com/wireguard/windows v0.5.4-0.20230123132234-dcc0eb72a04b // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gvisor.dev/gvisor v0.0.0-20260506221003-3f0d59b9fb9f // indirect
)

replace (
	github.com/apernet/quic-go => github.com/yaling888/quic-hy2 v0.59.359
	github.com/yaling888/quirktiva => ../
)
