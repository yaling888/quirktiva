package outbound

type WireGuardOption struct {
	BasicOption
	Name             string   `proxy:"name"`
	Server           string   `proxy:"server"`
	Port             int      `proxy:"port"`
	IP               string   `proxy:"ip,omitempty"`
	IPv6             string   `proxy:"ipv6,omitempty"`
	PrivateKey       string   `proxy:"private-key"`
	PublicKey        string   `proxy:"public-key"`
	PresharedKey     string   `proxy:"preshared-key,omitempty"`
	DNS              []string `proxy:"dns,omitempty"`
	MTU              int      `proxy:"mtu,omitempty"`
	UDP              bool     `proxy:"udp,omitempty"`
	RemoteDnsResolve bool     `proxy:"remote-dns-resolve,omitempty"`
	Reserved         string   `proxy:"reserved,omitempty"`
}
