package env

import (
	"os"
	"strings"
	"testing"
)

func TestSanitizer_Sanitize(t *testing.T) {
	hostEnv := []string{
		"PATH=/usr/bin:.:./bin:/bin:/usr/local/bin",
		"TERM=xterm-256color",
		"LANG=en_US.UTF-8",
		"HOME=/Users/victim",
		"TMPDIR=/var/folders/temp",
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"DATABASE_URL=postgres://user:pass@localhost:5432/proddb",
		"GITHUB_TOKEN=ghp_secrettoken1234567890",
		"OPENAI_API_KEY=sk-proj-supersecretkey",
		"CUSTOM_ALLOWED_VAR=allowed_value",
	}

	cfg := Config{
		VirtualHome:  "/tmp/boxpkg-test/home",
		ScratchDir:   "/tmp/boxpkg-test/tmp",
		StagingCache: "/tmp/boxpkg-test/cache",
		ProxyURL:     "http://127.0.0.1:18443",
		KeepEnv:      []string{"CUSTOM_ALLOWED_VAR"},
	}

	sanitizer := NewSanitizer(cfg)
	sanitized := sanitizer.Sanitize(hostEnv)

	envMap := make(map[string]string)
	for _, entry := range sanitized {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	// 1. Secrets must be dropped
	forbidden := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"DATABASE_URL",
		"GITHUB_TOKEN",
		"OPENAI_API_KEY",
	}
	for _, key := range forbidden {
		if val, exists := envMap[key]; exists {
			t.Errorf("Security violation: %s leaked into sandbox environment: %s", key, val)
		}
	}

	// 2. Safe variables must be preserved
	if envMap["TERM"] != "xterm-256color" {
		t.Errorf("Expected TERM to be preserved, got: %s", envMap["TERM"])
	}
	if envMap["LANG"] != "en_US.UTF-8" {
		t.Errorf("Expected LANG to be preserved, got: %s", envMap["LANG"])
	}

	// 3. PATH must be sanitized of relative paths
	expectedPath := strings.Join([]string{"/usr/bin", "/bin", "/usr/local/bin"}, string(os.PathListSeparator))
	if envMap["PATH"] != expectedPath {
		t.Errorf("PATH was not properly sanitized. Expected %q, got %q", expectedPath, envMap["PATH"])
	}

	// 4. Virtual paths must be injected
	if envMap["HOME"] != "/tmp/boxpkg-test/home" {
		t.Errorf("Expected virtual HOME, got %s", envMap["HOME"])
	}
	if envMap["TMPDIR"] != "/tmp/boxpkg-test/tmp" {
		t.Errorf("Expected virtual TMPDIR, got %s", envMap["TMPDIR"])
	}

	// 5. Ephemeral cache redirects must be present
	if envMap["npm_config_cache"] != "/tmp/boxpkg-test/cache/npm" {
		t.Errorf("Expected npm_config_cache redirect, got %s", envMap["npm_config_cache"])
	}
	if envMap["PIP_CACHE_DIR"] != "/tmp/boxpkg-test/cache/pip" {
		t.Errorf("Expected PIP_CACHE_DIR redirect, got %s", envMap["PIP_CACHE_DIR"])
	}

	// 6. Proxy configuration injected
	if envMap["HTTP_PROXY"] != "http://127.0.0.1:18443" {
		t.Errorf("Expected HTTP_PROXY to be set, got %s", envMap["HTTP_PROXY"])
	}

	// 7. Nesting sentinel must be set
	if envMap["__AIRLOCK_ACTIVE"] != "1" {
		t.Errorf("Expected __AIRLOCK_ACTIVE=1, got %s", envMap["__AIRLOCK_ACTIVE"])
	}

	// 8. Custom kept env preserved
	if envMap["CUSTOM_ALLOWED_VAR"] != "allowed_value" {
		t.Errorf("Expected CUSTOM_ALLOWED_VAR to be preserved, got %s", envMap["CUSTOM_ALLOWED_VAR"])
	}
}

func TestSanitizePath(t *testing.T) {
	input := "/bin:.:./scripts:../other:/usr/bin:/:   :/usr/local/bin"
	clean := SanitizePath(input)
	expected := strings.Join([]string{"/bin", "/usr/bin", "/usr/local/bin"}, string(os.PathListSeparator))
	if clean != expected {
		t.Errorf("Expected %q, got %q", expected, clean)
	}
}
