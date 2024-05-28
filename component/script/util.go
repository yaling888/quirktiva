package script

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/yaling888/quirktiva/component/ipset"
	"github.com/yaling888/quirktiva/component/mmdb"
	P "github.com/yaling888/quirktiva/component/process"
	"github.com/yaling888/quirktiva/component/resolver"
	C "github.com/yaling888/quirktiva/constant"
)

func uResolveIP(mtd *C.Metadata, host string) string {
	var ip string

	if mtd.Resolved() {
		ip = mtd.DstIP.String()
	} else if rAddrs, err := resolver.LookupIP(context.Background(), host); err == nil {
		addr := rAddrs[0]
		if l := len(rAddrs); l > 1 && mtd.NetWork != C.UDP {
			addr = rAddrs[rand.IntN(l)]
		}
		ip = addr.String()
		mtd.DstIP = addr
	}

	return ip
}

func uInCidr(ip, cidr string) (bool, error) {
	var (
		mIP   netip.Addr
		mCidr netip.Prefix
		err   error
	)

	if mIP, err = netip.ParseAddr(ip); err != nil {
		return false, err
	}

	if mCidr, err = netip.ParsePrefix(cidr); err != nil {
		return false, err
	}

	return mCidr.Contains(mIP), nil
}

func uInIPSet(name, ip string) bool {
	dstIP, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	rs, err := ipset.Test(name, dstIP)
	if err != nil {
		return false
	}
	return rs
}

func uGeoIP(ip string) string {
	dstIP, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}

	if dstIP.IsPrivate() ||
		dstIP.IsUnspecified() ||
		dstIP.IsLoopback() ||
		dstIP.IsMulticast() ||
		dstIP.IsLinkLocalUnicast() ||
		resolver.IsFakeBroadcastIP(dstIP) {

		return "LAN"
	}

	record, _ := mmdb.Instance().Country(dstIP.AsSlice())

	return strings.ToUpper(record.Country.IsoCode)
}

func uMatchProvider(mtd *C.Metadata, name string) (bool, error) {
	providerName := strings.ToLower(name)

	rule := C.GetScriptRuleProviders()[providerName]
	if rule == nil {
		return false, fmt.Errorf("call match_provider error: rule provider [%s] not found", name)
	}

	return rule.Match(mtd), nil
}

func uResolveProcess(mtd *C.Metadata) {
	if mtd.ProcessPath != "" || !mtd.OriginDst.IsValid() {
		return
	}

	path, err := P.FindProcessPath(mtd.NetWork.String(), netip.AddrPortFrom(mtd.SrcIP, uint16(mtd.SrcPort)), mtd.OriginDst)
	if err == nil {
		mtd.Process = filepath.Base(path)
		mtd.ProcessPath = path
	}
}
