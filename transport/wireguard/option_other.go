//go:build !freebsd && !openbsd && !nogvisor

package wireguard

func getListenIP(_ string, _ string) (string, error) {
	return "", nil
}
