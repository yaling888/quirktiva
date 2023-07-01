package script

import (
	"strconv"
	"time"

	"github.com/antonmedv/expr/ast"

	C "github.com/Dreamacro/clash/constant"
)

type (
	scStringFunc          = func(string) string
	scStringBoolFunc      = func(string) (bool, error)
	scEmptyFunc           = func() string
	scStringStringFunc    = func(string, string) bool
	scStringStringErrFunc = func(string, string) (bool, error)
)

type shortcutEnvironment struct {
	Network      string   `expr:"network"`
	Type         string   `expr:"type"`
	SrcIP        string   `expr:"src_ip"`
	DstIP        string   `expr:"dst_ip"`
	SrcPort      uint16   `expr:"src_port"`
	DstPort      uint16   `expr:"dst_port"`
	Host         string   `expr:"host"`
	ProcessName  string   `expr:"process_name"`
	ProcessPath  string   `expr:"process_path"`
	UserAgent    string   `expr:"user_agent"`
	SpecialProxy string   `expr:"special_proxy"`
	Now          timeExpr `expr:"now"`

	ResolveIP          scStringFunc          `expr:"resolve_ip"`
	InCidr             scStringStringErrFunc `expr:"in_cidr"`
	InIPSet            scStringStringFunc    `expr:"in_ipset"`
	GeoIP              scStringFunc          `expr:"geoip"`
	MatchProvider      scStringBoolFunc      `expr:"match_provider"`
	ResolveProcessName scEmptyFunc           `expr:"resolve_process_name"`
	ResolveProcessPath scEmptyFunc           `expr:"resolve_process_path"`
}

type timeExpr struct {
	Year       int   `expr:"year"`
	Month      int   `expr:"month"`
	Day        int   `expr:"day"`
	Hour       int   `expr:"hour"`
	Minute     int   `expr:"minute"`
	Second     int   `expr:"second"`
	Nanosecond int   `expr:"nanosecond"`
	Unix       int64 `expr:"unix"`
	UnixNano   int64 `expr:"unix_nano"`
	Weekday    int   `expr:"weekday"`
}

type stringInString struct{}

func (*stringInString) Visit(node *ast.Node) {
	switch n := (*node).(type) {
	case *ast.BinaryNode:
		if n.Operator == "in" {
			switch n.Right.(type) {
			case *ast.StringNode, *ast.IdentifierNode, *ast.CallNode:
				if _, ok := n.Left.(*ast.StringNode); ok {
					ast.Patch(node, &ast.BinaryNode{
						Operator: "contains",
						Left:     n.Right,
						Right:    n.Left,
					})
				}
			}
		}
	}
}

func parseEnv(mtd *C.Metadata) shortcutEnvironment {
	env := shortcutEnvironment{
		Network:      mtd.NetWork.String(),
		Type:         mtd.Type.String(),
		Host:         mtd.Host,
		ProcessName:  mtd.Process,
		ProcessPath:  mtd.ProcessPath,
		UserAgent:    mtd.UserAgent,
		SpecialProxy: mtd.SpecialProxy,
		Now:          parseTimeExpr(),
	}

	if mtd.SrcIP.IsValid() {
		env.SrcIP = mtd.SrcIP.String()
	}

	if mtd.DstIP.IsValid() {
		env.DstIP = mtd.DstIP.String()
	}

	srcPort, err := strconv.ParseUint(mtd.SrcPort, 10, 16)
	if err == nil {
		env.SrcPort = uint16(srcPort)
	}

	dstPort, err := strconv.ParseUint(mtd.DstPort, 10, 16)
	if err == nil {
		env.DstPort = uint16(dstPort)
	}

	env.InCidr = uInCidr
	env.InIPSet = uInIPSet
	env.GeoIP = uGeoIP

	env.ResolveIP = func(host string) string {
		return uResolveIP(mtd, host)
	}

	env.MatchProvider = func(name string) (bool, error) {
		return uMatchProvider(mtd, name)
	}

	env.ResolveProcessName = func() string {
		uResolveProcess(mtd)
		return mtd.Process
	}

	env.ResolveProcessPath = func() string {
		uResolveProcess(mtd)
		return mtd.ProcessPath
	}

	return env
}

func parseTimeExpr() timeExpr {
	t := time.Now()
	return timeExpr{
		Year:       t.Year(),
		Month:      int(t.Month()),
		Day:        t.Day(),
		Hour:       t.Hour(),
		Minute:     t.Minute(),
		Second:     t.Second(),
		Nanosecond: t.Nanosecond(),
		Unix:       t.Unix(),
		UnixNano:   t.UnixNano(),
		Weekday:    int(t.Weekday()),
	}
}
