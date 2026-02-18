package constant

import (
	regexp "github.com/dlclark/regexp2"
	"github.com/expr-lang/expr/vm"
)

var RewriteTypeMapping = map[string]RewriteType{
	MitmReject.String():             MitmReject,
	MitmReject200.String():          MitmReject200,
	MitmReject204.String():          MitmReject204,
	MitmRejectImg.String():          MitmRejectImg,
	MitmRejectDict.String():         MitmRejectDict,
	MitmRejectArray.String():        MitmRejectArray,
	Mitm302.String():                Mitm302,
	Mitm307.String():                Mitm307,
	MitmRequestHeader.String():      MitmRequestHeader,
	MitmRequestHeaderJSON.String():  MitmRequestHeaderJSON,
	MitmRequestBody.String():        MitmRequestBody,
	MitmRequestBodyJSON.String():    MitmRequestBodyJSON,
	MitmResponseHeader.String():     MitmResponseHeader,
	MitmResponseHeaderJSON.String(): MitmResponseHeaderJSON,
	MitmResponseBody.String():       MitmResponseBody,
	MitmResponseBodyJSON.String():   MitmResponseBodyJSON,
}

const (
	MitmReject RewriteType = iota + 1
	MitmReject200
	MitmReject204
	MitmRejectImg
	MitmRejectDict
	MitmRejectArray

	Mitm302
	Mitm307

	MitmRequestHeader
	MitmRequestHeaderJSON
	MitmRequestBody
	MitmRequestBodyJSON

	MitmResponseHeader
	MitmResponseHeaderJSON
	MitmResponseBody
	MitmResponseBodyJSON
)

type RewriteType int

func (rt RewriteType) String() string {
	switch rt {
	case MitmReject:
		return "reject" // 404
	case MitmReject200:
		return "reject-200"
	case MitmReject204:
		return "reject-204"
	case MitmRejectImg:
		return "reject-img"
	case MitmRejectDict:
		return "reject-dict"
	case MitmRejectArray:
		return "reject-array"
	case Mitm302:
		return "302"
	case Mitm307:
		return "307"
	case MitmRequestHeader:
		return "request-header"
	case MitmRequestHeaderJSON:
		return "json-request-header"
	case MitmRequestBody:
		return "request-body"
	case MitmRequestBodyJSON:
		return "json-request-body"
	case MitmResponseHeader:
		return "response-header"
	case MitmResponseHeaderJSON:
		return "json-response-header"
	case MitmResponseBody:
		return "response-body"
	case MitmResponseBodyJSON:
		return "json-response-body"
	default:
		return "Unknown"
	}
}

type Rewrite interface {
	URLRegx() *regexp.Regexp
	RuleType() RewriteType
	RuleRegx() []*regexp.Regexp
	RulePayload() []string
	RuleExpr() *vm.Program
	ReplaceURLPayload([]string) string
	ReplaceSubPayload(string) (string, bool)
}

type RewriteRule interface {
	SearchInRequest(func(Rewrite) bool) bool
	SearchInResponse(func(Rewrite) bool) bool
}
