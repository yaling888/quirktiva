package tunnel

import (
	"errors"
	"net"
	"net/netip"
	"time"

	N "github.com/yaling888/clash/common/net"
	"github.com/yaling888/clash/common/pool"
	C "github.com/yaling888/clash/constant"
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

func handleUDPToLocal(packet C.UDPPacket, pc net.PacketConn, key, rKey string, oAddr, fAddr netip.Addr) {
	bufP := pool.GetNetBuf()
	defer func() {
		_ = pc.Close()
		natTable.Delete(key)
		pool.PutNetBuf(bufP)

		if rKey != "" {
			addrTable.Delete(rKey)
		}
	}()

	for {
		_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))
		n, from, err := pc.ReadFrom(*bufP)
		if err != nil {
			return
		}

		fromUDPAddr := *(from.(*net.UDPAddr))
		if fAddr.IsValid() {
			fromAddr, _ := netip.AddrFromSlice(fromUDPAddr.IP)
			fromAddr = fromAddr.Unmap()
			if oAddr == fromAddr {
				fromUDPAddr.IP = fAddr.AsSlice()
				fromUDPAddr.Zone = fAddr.Zone()
			}
		}

		_, err = packet.WriteBack((*bufP)[:n], &fromUDPAddr)
		if err != nil {
			return
		}
	}
}

func handleSocket(ctx C.ConnContext, outbound net.Conn) {
	N.Relay(ctx.Conn(), outbound)
}
