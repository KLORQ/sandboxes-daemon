package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDefaultsAndFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	values, err := Load(path)
	if err != nil || values != (Values{}) {
		t.Fatalf("missing file = %+v, %v", values, err)
	}
	body := `# host settings
dns_upstream = "1.1.1.1:53"
default_policy_profile = "balanced"
default_cpus = 4
default_memory_mib = 2048
docker_volume_size = "20g"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	values, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if values.DNSUpstream != "1.1.1.1:53" || values.DefaultPolicyProfile != "balanced" ||
		values.DefaultCPUs != 4 || values.DefaultMemoryMiB != 2048 || values.DockerVolumeSize != "20g" {
		t.Fatalf("values=%+v", values)
	}
}

func TestLoadRejectsUnsafeAndUnknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.toml")
	if err := os.WriteFile(path, []byte("unknown = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("unknown key error=%v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("permissions error=%v", err)
	}
}
