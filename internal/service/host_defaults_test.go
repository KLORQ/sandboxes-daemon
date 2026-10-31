package service

import "testing"

func TestEffectiveHostResources(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cpus       int
		memory     uint64
		wantCPUs   uint32
		wantMemory uint32
	}{
		{"normal", 14, 36 * 1024 * 1024 * 1024, 14, 18 * 1024},
		{"zero-cpu", 0, 8 * 1024 * 1024 * 1024, 1, 4096},
		{"cpu-clamp", 128, 8 * 1024 * 1024 * 1024, 64, 4096},
		{"memory-min", 4, 256 * 1024 * 1024, 4, 512},
		{"memory-max", 4, 128 * 1024 * 1024 * 1024, 4, 32 * 1024},
		{"no-memory", 4, 0, 4, 512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cpus, memory := effectiveHostResources(tc.cpus, tc.memory)
			if cpus != tc.wantCPUs || memory != tc.wantMemory {
				t.Fatalf("got %d CPU/%d MiB, want %d/%d", cpus, memory, tc.wantCPUs, tc.wantMemory)
			}
		})
	}
}
