//go:build !nogvisor && linux

package xdp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpf -tags linux af_xdp_sock af_xdp_sock.ebpf.c
