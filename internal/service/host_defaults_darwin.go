//go:build darwin

package service

import (
	"runtime"

	"golang.org/x/sys/unix"
)

func hostResourceDefaults() (uint32, uint32) {
	memory, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return fallbackHostResources()
	}
	return effectiveHostResources(runtime.NumCPU(), memory)
}
