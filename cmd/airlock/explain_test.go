package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bonjoski/airlock/pkg/ux"
)

func TestAirlockExplain_AllTopicsAndFlags(t *testing.T) {
	topics := []string{"sandbox", "shims", "seatbelt", "landlock", "ssh", "worktree"}

	for _, topic := range topics {
		t.Run(topic+"/default", func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := runExplain([]string{topic}, &out, &errBuf)
			if code != 0 {
				t.Fatalf("runExplain(%q) exit=%d stderr=%s", topic, code, errBuf.String())
			}
			rendered := out.String()
			if strings.ContainsRune(rendered, 0x1b) {
				t.Fatalf("explain output contains raw ESC: %q", rendered)
			}
			lines := strings.Split(strings.TrimSuffix(rendered, "\n"), "\n")
			if len(lines) > 3 {
				t.Fatalf("default explain(%q) exceeded 3 lines (%d):\n%s", topic, len(lines), rendered)
			}
		})

		t.Run(topic+"/why", func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := runExplain([]string{topic, "--why"}, &out, &errBuf)
			if code != 0 {
				t.Fatalf("runExplain(%q, --why) exit=%d", topic, code)
			}
			if !strings.Contains(out.String(), "Deep Dive (--why):") {
				t.Fatalf("expected Deep Dive (--why) section for %q, got:\n%s", topic, out.String())
			}
		})

		t.Run(topic+"/json", func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := runExplain([]string{topic, "--json"}, &out, &errBuf)
			if code != 0 {
				t.Fatalf("runExplain(%q, --json) exit=%d", topic, code)
			}
			if strings.ContainsRune(out.String(), 0x1b) {
				t.Fatalf("JSON explain output contains raw ESC")
			}
			var decoded ux.FixForwardError
			if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
				t.Fatalf("invalid JSON for %q: %v", topic, err)
			}
			if decoded.Tool != "airlock" || decoded.Code == "" || decoded.Summary == "" || decoded.RemediationCmd == "" || decoded.WhyOneLiner == "" {
				t.Fatalf("incomplete FixForwardError JSON for %q: %+v", topic, decoded)
			}
		})
	}
}

func TestAirlockExplain_DefaultAndUnknownTopic(t *testing.T) {
	// Default (no topic) succeeds with valid JSON
	var out, errBuf bytes.Buffer
	if code := runExplain([]string{"--json"}, &out, &errBuf); code != 0 {
		t.Fatalf("expected default explain --json exit 0, got %d", code)
	}
	var def ux.FixForwardError
	if err := json.Unmarshal(out.Bytes(), &def); err != nil {
		t.Fatalf("default explain JSON invalid: %v", err)
	}
	if def.Code != "AIRLOCK_EXPLAIN_SANDBOX" {
		t.Fatalf("expected AIRLOCK_EXPLAIN_SANDBOX, got %q", def.Code)
	}

	// Unknown topic fails closed with FixForwardError JSON
	out.Reset()
	errBuf.Reset()
	if code := runExplain([]string{"nonexistent-topic", "--json"}, &out, &errBuf); code != 1 {
		t.Fatalf("expected unknown topic exit 1, got %d", code)
	}
	var unk ux.FixForwardError
	if err := json.Unmarshal(errBuf.Bytes(), &unk); err != nil {
		t.Fatalf("unknown topic stderr JSON invalid: %v (raw: %q)", err, errBuf.String())
	}
	if unk.Code != "AIRLOCK_EXPLAIN_UNKNOWN_TOPIC" || unk.RemediationCmd == "" || unk.WhyOneLiner == "" {
		t.Fatalf("unexpected unknown topic FixForwardError: %+v", unk)
	}
}
