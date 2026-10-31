//go:build !darwin && !linux

package service

func hostResourceDefaults() (uint32, uint32) {
	return fallbackHostResources()
}
