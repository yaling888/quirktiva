package tunnel

import (
	"errors"
	"net"
	"net/netip"
	"time"

	N "github.com/yaling888/quirktiva/common/net"
	"github.com/yaling888/quirktiva/common/pool"
	C "github.com/yaling888/quirktiva/constant"
)

func handleUDPToRemote(packet C.UDPPacket, pc C.PacketConn, metadata *C.Metadata) error {
	if packet.Data() == nil {
		return errors.New("invalid udp payload")
	}

	addr := metadata.UDPAddr()
	if addr == nil {
		return errors.New("invalid udp addr")
	}

	if _, err := pc.WriteTo(*packet.Data(), addr); err != nil {
		return err
	}
	// reset timeout
	_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))

	return nil
}

func handleUDPToLocal(packet C.UDPPacket, pc net.PacketConn, key string, oAddr, fAddr netip.Addr) {
	bufP := pool.GetNetBuf()
	defer func() {
		_ = pc.Close()
		natTable.Delete(key)
		addrTable.Delete(key)
		pool.PutNetBuf(bufP)
	}()

	for {
		_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))
		n, from, err := pc.ReadFrom(*bufP)
		if err != nil {
			return
		}

		var rAddrPort netip.AddrPort
		switch fromAddr := from.(type) {
		case *net.UDPAddr:
			ip, _ := netip.AddrFromSlice(fromAddr.IP)
			rAddrPort = netip.AddrPortFrom(ip.Unmap(), uint16(fromAddr.Port))
		case *net.TCPAddr:
			ip, _ := netip.AddrFromSlice(fromAddr.IP)
			rAddrPort = netip.AddrPortFrom(ip.Unmap(), uint16(fromAddr.Port))
		default:
			if rAddrPort, err = netip.ParseAddrPort(fromAddr.String()); err != nil {
				return
			}
		}

		if fAddr.IsValid() && oAddr == rAddrPort.Addr() {
			rAddrPort = netip.AddrPortFrom(fAddr, rAddrPort.Port())
		}

		_, err = packet.WriteBack((*bufP)[:n], net.UDPAddrFromAddrPort(rAddrPort))
		if err != nil {
			return
		}
	}
}

func handleSocket(ctx C.ConnContext, outbound net.Conn) {
	N.Relay(ctx.Conn(), outbound)
}
