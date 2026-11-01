package service

import "runtime"

// EffectiveHostResourcesForTest exposes the pure formula for tests.
func effectiveHostResources(hostCPUs int, hostMemoryBytes uint64) (uint32, uint32) {
	cpus := hostCPUs
	if cpus < 1 {
		cpus = 1
	}
	if cpus > 64 {
		cpus = 64
	}
	memoryMiB := hostMemoryBytes / 2 / (1024 * 1024)
	if memoryMiB < 512 {
		memoryMiB = 512
	}
	if memoryMiB > 32*1024 {
		memoryMiB = 32 * 1024
	}
	return uint32(cpus), uint32(memoryMiB)
}

func fallbackHostResources() (uint32, uint32) {
	return effectiveHostResources(runtime.NumCPU(), 0)
}
