//go:build linux

package service

import (
	"runtime"

	"golang.org/x/sys/unix"
)

func hostResourceDefaults() (uint32, uint32) {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return fallbackHostResources()
	}
	memory := info.Totalram * uint64(info.Unit)
	return effectiveHostResources(runtime.NumCPU(), memory)
}
