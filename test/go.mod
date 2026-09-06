module quirktiva-test

go 1.27.1

require (
	github.com/miekg/dns v1.1.73
	github.com/moby/moby/api v1.56.0
	github.com/moby/moby/client v0.6.0
	github.com/stretchr/testify v1.12.1
	github.com/yaling888/quirktiva v0.0.0
	go.uber.org/automaxprocs v1.6.0
	golang.org/x/net v0.58.1-0.20260904215552-c23af1b9b8cc
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/andybalholm/brotli v1.2.3 // indirect
	github.com/apernet/hysteria/core/v2 v2.12.2 // indirect
	github.com/apernet/hysteria/extras/v2 v2.12.2 // indirect
	github.com/apernet/quic-go v0.61.1-0.20260806010916-184d081eef3e // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cilium/ebpf v0.22.0 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/dlclark/regexp2/v2 v2.7.2 // indirect
	github.com/docker/go-connections v0.7.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/expr-lang/expr v1.17.8 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/insomniacslk/dhcp v0.0.0-20260901064844-234b97448fae // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/oschwald/geoip2-golang/v2 v2.3.0 // indirect
	github.com/oschwald/maxminddb-golang/v2 v2.5.0 // indirect
	github.com/phuslu/log v1.0.128 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.62.0 // indirect
	github.com/refraction-networking/utls v1.8.3-0.20260301010127-aa6edf4b11af // indirect
	github.com/sagernet/sing v0.9.2 // indirect
	github.com/samber/lo v1.53.0 // indirect
	github.com/stretchr/objx v0.5.3 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	go.etcd.io/bbolt v1.5.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.67.0 // indirect
	go.opentelemetry.io/otel v1.43.0 // indirect
	go.opentelemetry.io/otel/metric v1.43.0 // indirect
	go.opentelemetry.io/otel/trace v1.43.0 // indirect
	go.starlark.net v0.0.0-20260904161901-6ecada49e42f // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/exp v0.0.0-20260820142414-ca536658362e // indirect
	golang.org/x/sync v0.22.1-0.20260831030441-f75267d8412f // indirect
	golang.org/x/sys v0.47.1-0.20260831194343-613e2570718e // indirect
	golang.org/x/text v0.41.1-0.20260828012921-f53c31601f90 // indirect
	golang.org/x/time v0.15.1-0.20260819171618-fb013b3d305a // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446 // indirect
	golang.zx2c4.com/wireguard/windows v0.5.4-0.20230123132234-dcc0eb72a04b // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gvisor.dev/gvisor v0.0.0-20260906120324-45bde0d1defa // indirect
)

replace github.com/yaling888/quirktiva => ../

replace github.com/apernet/quic-go => github.com/yaling888/quic-hy2 v0.62.0
