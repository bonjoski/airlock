package interactive

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestTerminalPrompter_Grants(t *testing.T) {
	cases := []struct {
		input    string
		expected Grant
	}{
		{"y\n", GrantOnce},
		{"yes\n", GrantOnce},
		{"a\n", GrantSession},
		{"always\n", GrantSession},
		{"s\n", GrantPersist},
		{"save\n", GrantPersist},
		{"n\n", GrantDeny},
		{"\n", GrantDeny},
		{"invalid\n", GrantDeny},
	}

	for _, c := range cases {
		in := strings.NewReader(c.input)
		var out bytes.Buffer

		prompter := &TerminalPrompter{
			In:      in,
			Out:     &out,
			Timeout: 2 * time.Second,
		}

		grant := prompter.PromptDomain("test.example.com")
		if grant != c.expected {
			t.Errorf("PromptDomain for input %q = %v; want %v", c.input, grant, c.expected)
		}
	}
}

func TestTerminalPrompter_Timeout(t *testing.T) {
	prompter := &TerminalPrompter{
		In:      strings.NewReader(""),
		Out:     new(bytes.Buffer),
		Timeout: 50 * time.Millisecond,
	}

	grant := prompter.PromptDomain("timeout.example.com")
	if grant != GrantDeny {
		t.Fatalf("expected GrantDeny on timeout/EOF, got %v", grant)
	}
}
