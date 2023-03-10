package script

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/phuslu/log"
	"go.starlark.net/lib/time"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/Dreamacro/clash/component/mmdb"
	P "github.com/Dreamacro/clash/component/process"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
)

var moduleContext *starlarkstruct.Module

func init() {
	var (
		resolveIPMethod   = starlark.NewBuiltin("resolve_ip", resolveIP)
		processNameMethod = starlark.NewBuiltin("resolve_process_name", resolveProcessName)
		processPathMethod = starlark.NewBuiltin("resolve_process_path", resolveProcessPath)
		GeoIPMethod       = starlark.NewBuiltin("geoip", geoIP)
	)

	moduleContext = &starlarkstruct.Module{
		Name: "clash_ctx",
		Members: starlark.StringDict{
			"resolve_ip":           resolveIPMethod,
			"resolve_process_name": processNameMethod,
			"resolve_process_path": processPathMethod,
			"geoip":                GeoIPMethod,
			"log":                  starlark.NewBuiltin("log", log_),

			"proxy_providers": newProxyProviders(),
			"rule_providers":  newRuleProviders(),
		},
	}

	starlark.Universe["time"] = time.Module
	starlark.Universe["resolve_ip"] = resolveIPMethod
	starlark.Universe["resolve_process_name"] = processNameMethod
	starlark.Universe["resolve_process_path"] = processPathMethod
	starlark.Universe["in_cidr"] = starlark.NewBuiltin("in_cidr", inCidr)
	starlark.Universe["geoip"] = GeoIPMethod
	starlark.Universe["match_provider"] = starlark.NewBuiltin("match_provider", matchRuleProviderByShortcut)
	starlark.Universe["_clash_ctx"] = moduleContext
}

func resolveIP(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &s); err != nil {
		return nil, fmt.Errorf("call resolve_ip error: %w", err)
	}

	var ip string

	obj := thread.Local(metadataLocalKey)
	if obj == nil {
		return nil, fmt.Errorf("call resolve_ip error: metadata is nil")
	}

	mtd := obj.(*C.Metadata)
	if mtd.Resolved() {
		ip = mtd.DstIP.String()
	} else if rAddrs, err := resolver.LookupIP(context.Background(), s); err == nil {
		addr := rAddrs[0]
		if l := len(rAddrs); l > 1 && mtd.NetWork != C.UDP {
			addr = rAddrs[rand.Intn(l)]
		}
		ip = addr.String()
		mtd.DstIP = addr
	}

	return starlark.String(ip), nil
}

func resolveProcessName(thread *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	obj := thread.Local(metadataLocalKey)
	if obj == nil {
		return nil, fmt.Errorf("call resolve_process_name error: metadata is nil")
	}

	mtd := obj.(*C.Metadata)

	if mtd.Process == "" {
		if srcPort, err := strconv.ParseUint(mtd.SrcPort, 10, 16); err == nil {
			if path, err1 := P.FindProcessName(mtd.NetWork.String(), mtd.SrcIP, int(srcPort)); err1 == nil {
				mtd.Process = filepath.Base(path)
				mtd.ProcessPath = path
			}
		}
	}

	return starlark.String(mtd.Process), nil
}

func resolveProcessPath(thread *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	obj := thread.Local(metadataLocalKey)
	if obj == nil {
		return nil, fmt.Errorf("call resolve_process_path error: metadata is nil")
	}

	mtd := obj.(*C.Metadata)

	if mtd.ProcessPath == "" {
		if srcPort, err := strconv.ParseUint(mtd.SrcPort, 10, 16); err == nil {
			if path, err1 := P.FindProcessName(mtd.NetWork.String(), mtd.SrcIP, int(srcPort)); err1 == nil {
				mtd.Process = filepath.Base(path)
				mtd.ProcessPath = path
			}
		}
	}

	return starlark.String(mtd.ProcessPath), nil
}

func geoIP(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (_ starlark.Value, err error) {
	var s string
	if err = starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &s); err != nil {
		return nil, fmt.Errorf("call geo_ip error: %w", err)
	}

	var dstIP netip.Addr
	dstIP, err = netip.ParseAddr(s)
	if err != nil {
		return starlark.String(fmt.Sprintf("input ip '%s' is invalid", s)), nil
	}

	if dstIP.IsPrivate() ||
		dstIP.IsUnspecified() ||
		dstIP.IsLoopback() ||
		dstIP.IsMulticast() ||
		dstIP.IsLinkLocalUnicast() ||
		resolver.IsFakeBroadcastIP(dstIP) {

		return starlark.String("LAN"), nil
	}

	record, _ := mmdb.Instance().Country(dstIP.AsSlice())
	rc := strings.ToUpper(record.Country.IsoCode)

	return starlark.String(rc), nil
}

func log_(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &s); err != nil {
		return nil, fmt.Errorf("call log error: %w", err)
	}

	log.Info().Msg(s)

	return starlark.None, nil
}

func inCidr(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (_ starlark.Value, err error) {
	var (
		s1, s2 string
		ip     netip.Addr
		cidr   netip.Prefix
	)

	defer func() {
		if err != nil {
			err = fmt.Errorf("call in_cidr error: %w", err)
		}
	}()

	if err = starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 2, &s1, &s2); err != nil {
		return
	}

	if ip, err = netip.ParseAddr(s1); err != nil {
		return
	}
	if cidr, err = netip.ParsePrefix(s2); err != nil {
		return
	}

	return starlark.Bool(cidr.Contains(ip)), nil
}

func matchRuleProvider(thread *starlark.Thread, b *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	providerName := b.Name()
	providerName = strings.TrimPrefix(providerName, "geosite:")

	rule := C.GetScriptRuleProviders()[providerName]
	if rule == nil {
		return nil, fmt.Errorf("call match_provider error: rule provider [%s] not found", providerName)
	}

	mtd := thread.Local(metadataLocalKey)
	if mtd == nil {
		return nil, fmt.Errorf("call match_provider error: metadata is nil")
	}

	return starlark.Bool(rule.Match(mtd.(*C.Metadata))), nil
}

func matchRuleProviderByShortcut(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &s); err != nil {
		return nil, fmt.Errorf("call match_provider error: %w", err)
	}

	providerName := s
	providerName = strings.TrimPrefix(providerName, "geosite:")

	rule := C.GetScriptRuleProviders()[providerName]
	if rule == nil {
		return nil, fmt.Errorf("call match_provider error: rule provider [%s] not found", providerName)
	}

	mtd := thread.Local(metadataLocalKey)
	if mtd == nil {
		return nil, fmt.Errorf("call match_provider error: metadata is nil")
	}

	return starlark.Bool(rule.Match(mtd.(*C.Metadata))), nil
}

func metadataToStringDict(mtd *C.Metadata, dict starlark.StringDict) (starlark.StringDict, error) {
	srcPort, err := strconv.ParseUint(mtd.SrcPort, 10, 16)
	if err != nil {
		return nil, err
	}
	dstPort, err := strconv.ParseUint(mtd.DstPort, 10, 16)
	if err != nil {
		return nil, err
	}

	if dict == nil {
		dict = make(starlark.StringDict)
	}
	dict["type"] = starlark.String(mtd.Type.String())
	dict["network"] = starlark.String(mtd.NetWork.String())
	dict["host"] = starlark.String(mtd.Host)
	dict["process_name"] = starlark.String(mtd.Process)
	dict["process_path"] = starlark.String(mtd.ProcessPath)
	dict["src_ip"] = starlark.String(mtd.SrcIP.String())
	dict["src_port"] = starlark.MakeUint64(srcPort)

	var dstIP string
	if mtd.Resolved() {
		dstIP = mtd.DstIP.String()
	}
	dict["dst_ip"] = starlark.String(dstIP)
	dict["dst_port"] = starlark.MakeUint64(dstPort)
	dict["user_agent"] = starlark.String(mtd.UserAgent)
	dict["special_proxy"] = starlark.String(mtd.SpecialProxy)

	return dict, nil
}

func metadataToDict(mtd *C.Metadata) (val *starlark.Dict, err error) {
	dict := starlark.NewDict(9)
	err = dict.SetKey(starlark.String("type"), starlark.String(mtd.Type.String()))
	if err != nil {
		return
	}
	err = dict.SetKey(starlark.String("network"), starlark.String(mtd.NetWork.String()))
	if err != nil {
		return
	}
	err = dict.SetKey(starlark.String("host"), starlark.String(mtd.Host))
	if err != nil {
		return
	}
	err = dict.SetKey(starlark.String("src_ip"), starlark.String(mtd.SrcIP.String()))
	if err != nil {
		return
	}
	err = dict.SetKey(starlark.String("src_port"), starlark.String(mtd.SrcPort))
	if err != nil {
		return
	}

	var dstIP string
	if mtd.Resolved() {
		dstIP = mtd.DstIP.String()
	}
	err = dict.SetKey(starlark.String("dst_ip"), starlark.String(dstIP))
	if err != nil {
		return
	}
	err = dict.SetKey(starlark.String("dst_port"), starlark.String(mtd.DstPort))
	if err != nil {
		return
	}
	err = dict.SetKey(starlark.String("user_agent"), starlark.String(mtd.UserAgent))
	if err != nil {
		return
	}
	err = dict.SetKey(starlark.String("special_proxy"), starlark.String(mtd.SpecialProxy))
	if err != nil {
		return
	}

	val = dict
	return
}
