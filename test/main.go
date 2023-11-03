package main

import (
	"os"
	"runtime"
	"strconv"

	"go.uber.org/automaxprocs/maxprocs"
)

func main() {
	_, _ = maxprocs.Set(maxprocs.Logger(func(string, ...any) {}))
	_, _ = os.Stdout.Write([]byte(strconv.FormatInt(int64(runtime.GOMAXPROCS(0)), 10)))
}
