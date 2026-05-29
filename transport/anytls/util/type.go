package util

import (
	"context"
	"net"

	"github.com/yaling888/quirktiva/component/dialer"
)

type DialOutFunc = func(ctx context.Context, opts ...dialer.Option) (net.Conn, error)
