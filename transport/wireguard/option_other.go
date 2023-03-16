//go:build !freebsd && !openbsd

package wireguard

func getListenIP(_ string, _ string) (string, error) {
	return "", nil
}
