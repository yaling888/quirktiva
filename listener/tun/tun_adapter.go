package tun

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"runtime"
	"strings"

	"github.com/phuslu/log"

	"github.com/yaling888/quirktiva/adapter/inbound"
	"github.com/yaling888/quirktiva/common/cmd"
	"github.com/yaling888/quirktiva/component/dialer"
	"github.com/yaling888/quirktiva/component/resolver"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/listener/tun/device"
	"github.com/yaling888/quirktiva/listener/tun/device/tun"
	"github.com/yaling888/quirktiva/listener/tun/ipstack"
	"github.com/yaling888/quirktiva/listener/tun/ipstack/commons"
	"github.com/yaling888/quirktiva/listener/tun/ipstack/gvisor"
	"github.com/yaling888/quirktiva/listener/tun/ipstack/system"
)

// New TunAdapter
func New(
	tunConf *C.Tun,
	tcpIn chan<- C.ConnContext,
	udpIn chan<- *inbound.PacketAdapter,
	tunChangeCallback C.TUNChangeCallback,
) (ipstack.Stack, error) {
	var (
		tunAddress = netip.Prefix{}
		devName    = tunConf.Device
		stackType  = tunConf.Stack
		autoRoute  = tunConf.AutoRoute
		mtu        = 1<<16 - 1

		tunDevice device.Device
		tunStack  ipstack.Stack

		err error
	)

	defer func() {
		if err != nil {
			if tunStack != nil {
				_ = tunStack.Close()
			} else if tunDevice != nil {
				_ = tunDevice.Close2()
			}
		}
	}()

	defaultInterface := dialer.DefaultInterface.Load()
	if tunConf.AutoDetectInterface {
		commons.SetTunChangeCallback(tunChangeCallback)
		commons.StartDefaultInterfaceChangeMonitor()
		if defaultInterface == "" {
			commons.SetTunStatus(C.TunPaused)
			return nil, nil
		}
	} else if defaultInterface == "" {
		return nil, errors.New(
			"default interface not found, please assign value to `interface-name` or enable `auto-detect-interface`",
		)
	}

	if devName == "" {
		devName = generateDeviceName()
	}

	if tunConf.TunAddressPrefix != nil {
		tunAddress = *tunConf.TunAddressPrefix
	}

	if !tunAddress.IsValid() || !tunAddress.Addr().Is4() {
		tunAddress = netip.MustParsePrefix("198.18.0.1/16")
	}

	// open tun device
	tunDevice, err = parseDevice(devName, uint32(mtu))
	if err != nil {
		return nil, fmt.Errorf("can't open tun: %w", err)
	}

	devName = tunDevice.Name()

	// new ip stack
	switch stackType {
	case C.TunGvisor:
		err = tunDevice.UseEndpoint()
		if err != nil {
			return nil, fmt.Errorf("can't attach endpoint to tun: %w", err)
		}

		tunStack, err = gvisor.New(tunDevice, tunConf.DNSHijack, tunAddress, tcpIn, udpIn)
		if err != nil {
			return nil, fmt.Errorf("can't New gvisor stack: %w", err)
		}
	case C.TunSystem:
		err = tunDevice.UseIOBased()
		if err != nil {
			return nil, fmt.Errorf("can't New system stack: %w", err)
		}

		tunStack, err = system.New(tunDevice, tunConf.DNSHijack, tunAddress, tcpIn, udpIn)
		if err != nil {
			return nil, fmt.Errorf("can't New system stack: %w", err)
		}
	default:
		return nil, errors.New("unknown ip stack")
	}

	// setting address and routing
	err = commons.ConfigInterfaceAddress(tunDevice, tunAddress, mtu, autoRoute)
	if err != nil {
		return nil, fmt.Errorf("setting interface address and routing failed: %w", err)
	}

	if autoRoute {
		resolver.DisableIPv6 = true
	}

	tunConf.Device = devName
	setAtLatest(stackType, devName)

	log.Info().
		Str("iface", devName).
		NetIPAddr("gateway", tunAddress.Masked().Addr().Next()).
		Uint32("mtu", tunDevice.MTU()).
		Int("batchSize", tunDevice.BatchSize()).
		Bool("autoRoute", autoRoute).
		Bool("autoDetectInterface", tunConf.AutoDetectInterface).
		Str("ipStack", stackType.String()).
		Msg("[Inbound] tun listening")
	return tunStack, nil
}

func generateDeviceName() string {
	switch runtime.GOOS {
	case "darwin":
		return tun.Driver + "://utun"
	case "windows":
		return tun.Driver + "://Quirktiva"
	default:
		return tun.Driver + "://quirktiva"
	}
}

func parseDevice(s string, mtu uint32) (device.Device, error) {
	if !strings.Contains(s, "://") {
		s = fmt.Sprintf("%s://%s", tun.Driver /* default driver */, s)
	}

	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	name := u.Host
	return tun.Open(name, mtu)
}

func setAtLatest(stackType C.TUNStack, devName string) {
	switch runtime.GOOS {
	case "darwin":
		// _, _ = cmd.ExecCmd("/usr/sbin/sysctl -w net.inet.ip.forwarding=1")
		// _, _ = cmd.ExecCmd("/usr/sbin/sysctl -w net.inet6.ip6.forwarding=1")
		_, _ = cmd.ExecCmd("/bin/launchctl limit maxfiles 10240 unlimited")
	case "windows":
		if stackType != C.TunSystem {
			return
		}
		_, _ = cmd.ExecCmd("ipconfig /renew")
	case "linux":
		_, _ = cmd.ExecCmd("sysctl -w net.ipv4.ip_forward=1")
		_, _ = cmd.ExecCmd("sysctl -w net.ipv4.conf.all.forwarding=1")
		_, _ = cmd.ExecCmd("sysctl -w net.ipv4.conf.all.accept_local=1")
		_, _ = cmd.ExecCmd("sysctl -w net.ipv4.conf.all.accept_redirects=1")
		_, _ = cmd.ExecCmd("sysctl -w net.ipv4.conf.all.rp_filter=0")
		_, _ = cmd.ExecCmd(fmt.Sprintf("sysctl -w net.ipv4.conf.%s.forwarding=1", devName))
		_, _ = cmd.ExecCmd(fmt.Sprintf("sysctl -w net.ipv4.conf.%s.accept_local=1", devName))
		_, _ = cmd.ExecCmd(fmt.Sprintf("sysctl -w net.ipv4.conf.%s.accept_redirects=1", devName))
		_, _ = cmd.ExecCmd(fmt.Sprintf("sysctl -w net.ipv4.conf.%s.rp_filter=0", devName))
		//_, _ = cmd.ExecCmd("iptables -t filter -P FORWARD ACCEPT")
	}
}
