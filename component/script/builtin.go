package script

import (
	"fmt"

	"github.com/phuslu/log"
	"go.starlark.net/lib/time"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	C "github.com/yaling888/quirktiva/constant"
)

var moduleContext *starlarkstruct.Module

func init() {
	var (
		resolveIPMethod   = starlark.NewBuiltin("resolve_ip", resolveIP)
		inCidrMethod      = starlark.NewBuiltin("in_cidr", inCidr)
		inIPSetMethod     = starlark.NewBuiltin("in_ipset", inIPSet)
		geoIPMethod       = starlark.NewBuiltin("geoip", geoIP)
		processNameMethod = starlark.NewBuiltin("resolve_process_name", resolveProcessName)
		processPathMethod = starlark.NewBuiltin("resolve_process_path", resolveProcessPath)
	)

	moduleContext = &starlarkstruct.Module{
		Name: "clash_ctx",
		Members: starlark.StringDict{
			"resolve_ip":           resolveIPMethod,
			"in_cidr":              inCidrMethod,
			"in_ipset":             inIPSetMethod,
			"geoip":                geoIPMethod,
			"resolve_process_name": processNameMethod,
			"resolve_process_path": processPathMethod,
			"log":                  starlark.NewBuiltin("log", log_),

			"proxy_providers": newProxyProviders(),
			"rule_providers":  newRuleProviders(),
		},
	}

	starlark.Universe["time"] = time.Module
	starlark.Universe["resolve_ip"] = resolveIPMethod
	starlark.Universe["in_cidr"] = inCidrMethod
	starlark.Universe["in_ipset"] = inIPSetMethod
	starlark.Universe["geoip"] = geoIPMethod
	starlark.Universe["match_provider"] = starlark.NewBuiltin("match_provider", matchRuleProviderByShortcut)
	starlark.Universe["resolve_process_name"] = processNameMethod
	starlark.Universe["resolve_process_path"] = processPathMethod
	starlark.Universe["_clash_ctx"] = moduleContext
}

func resolveIP(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &s); err != nil {
		return nil, fmt.Errorf("call resolve_ip error: %w", err)
	}

	obj := thread.Local(metadataLocalKey)
	if obj == nil {
		return nil, fmt.Errorf("call resolve_ip error: metadata is nil")
	}

	mtd := obj.(*C.Metadata)

	ip := uResolveIP(mtd, s)

	return starlark.String(ip), nil
}

func resolveProcessName(thread *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	obj := thread.Local(metadataLocalKey)
	if obj == nil {
		return nil, fmt.Errorf("call resolve_process_name error: metadata is nil")
	}

	mtd := obj.(*C.Metadata)

	uResolveProcess(mtd)

	return starlark.String(mtd.Process), nil
}

func resolveProcessPath(thread *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	obj := thread.Local(metadataLocalKey)
	if obj == nil {
		return nil, fmt.Errorf("call resolve_process_path error: metadata is nil")
	}

	mtd := obj.(*C.Metadata)

	uResolveProcess(mtd)

	return starlark.String(mtd.ProcessPath), nil
}

func geoIP(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (_ starlark.Value, err error) {
	var s string
	if err = starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &s); err != nil {
		return nil, fmt.Errorf("call geo_ip error: %w", err)
	}

	return starlark.String(uGeoIP(s)), nil
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
	var s1, s2 string

	defer func() {
		if err != nil {
			err = fmt.Errorf("call in_cidr error: %w", err)
		}
	}()

	if err = starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 2, &s1, &s2); err != nil {
		return
	}

	var rs bool
	rs, err = uInCidr(s1, s2)
	if err != nil {
		return
	}

	return starlark.Bool(rs), nil
}

func inIPSet(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (_ starlark.Value, err error) {
	var s1, s2 string

	if err = starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 2, &s1, &s2); err != nil {
		return nil, fmt.Errorf("call in_ipset error: %w", err)
	}

	rs := uInIPSet(s1, s2)

	return starlark.Bool(rs), nil
}

func matchRuleProvider(thread *starlark.Thread, b *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	obj := thread.Local(metadataLocalKey)
	if obj == nil {
		return nil, fmt.Errorf("call match_provider error: metadata is nil")
	}

	mtd := obj.(*C.Metadata)

	rs, err := uMatchProvider(mtd, b.Name())
	if err != nil {
		return nil, err
	}

	return starlark.Bool(rs), nil
}

func matchRuleProviderByShortcut(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &s); err != nil {
		return nil, fmt.Errorf("call match_provider error: %w", err)
	}

	obj := thread.Local(metadataLocalKey)
	if obj == nil {
		return nil, fmt.Errorf("call match_provider error: metadata is nil")
	}

	mtd := obj.(*C.Metadata)

	rs, err := uMatchProvider(mtd, s)
	if err != nil {
		return nil, err
	}

	return starlark.Bool(rs), nil
}

func metadataToStringDict(mtd *C.Metadata, dict starlark.StringDict) (starlark.StringDict, error) {
	if dict == nil {
		dict = make(starlark.StringDict)
	}
	dict["type"] = starlark.String(mtd.Type.String())
	dict["network"] = starlark.String(mtd.NetWork.String())
	dict["host"] = starlark.String(mtd.Host)
	dict["process_name"] = starlark.String(mtd.Process)
	dict["process_path"] = starlark.String(mtd.ProcessPath)
	dict["src_ip"] = starlark.String(mtd.SrcIP.String())
	dict["src_port"] = starlark.MakeUint64(uint64(mtd.SrcPort))

	var dstIP string
	if mtd.Resolved() {
		dstIP = mtd.DstIP.String()
	}
	dict["dst_ip"] = starlark.String(dstIP)
	dict["dst_port"] = starlark.MakeUint64(uint64(mtd.DstPort))
	dict["user_agent"] = starlark.String(mtd.UserAgent)
	dict["special_proxy"] = starlark.String(mtd.SpecialProxy)
	dict["inbound_port"] = starlark.MakeUint64(uint64(mtd.OriginDst.Port()))

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
	err = dict.SetKey(starlark.String("src_port"), starlark.String(mtd.SrcPort.String()))
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
	err = dict.SetKey(starlark.String("dst_port"), starlark.String(mtd.DstPort.String()))
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
	err = dict.SetKey(starlark.String("inbound_port"), starlark.MakeUint64(uint64(mtd.OriginDst.Port())))
	if err != nil {
		return
	}

	val = dict
	return
}
