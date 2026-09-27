package proxy

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestEgressProxy_DomainWhitelisting(t *testing.T) {
	p, err := New([]string{"custom-registry.internal"})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	defer p.Close()

	if p.Port() <= 0 {
		t.Errorf("Expected valid port, got %d", p.Port())
	}

	// 1. Test connecting to an UNAPPROVED domain -> Expect 403 Forbidden
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p.Port()))
	if err != nil {
		t.Fatalf("Failed to dial proxy: %v", err)
	}
	defer conn.Close()

	req := "CONNECT c2.attacker.com:443 HTTP/1.1\r\nHost: c2.attacker.com:443\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("Failed to write CONNECT request: %v", err)
	}

	reader := bufio.NewReader(conn)
	respLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read proxy response: %v", err)
	}

	if !strings.Contains(respLine, "403 Forbidden") {
		t.Errorf("Expected 403 Forbidden for unapproved domain, got: %s", respLine)
	}
}

func TestEgressProxy_AllowedDomainCheck(t *testing.T) {
	p, err := New([]string{"example.com"})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	defer p.Close()

	// Direct allowed check
	if !p.isDomainAllowed("registry.npmjs.org") {
		t.Errorf("Expected registry.npmjs.org to be allowed")
	}
	if !p.isDomainAllowed("pypi.org") {
		t.Errorf("Expected pypi.org to be allowed")
	}
	if !p.isDomainAllowed("crates.io") {
		t.Errorf("Expected crates.io to be allowed")
	}
	if !p.isDomainAllowed("example.com") {
		t.Errorf("Expected custom domain example.com to be allowed")
	}
	if !p.isDomainAllowed("sub.example.com") {
		t.Errorf("Expected subdomain sub.example.com to be allowed")
	}

	// Disallowed check
	if p.isDomainAllowed("attacker.com") {
		t.Errorf("Expected attacker.com to be disallowed")
	}
	if p.isDomainAllowed("evilexample.com") {
		t.Errorf("Expected evilexample.com to be disallowed")
	}
}
