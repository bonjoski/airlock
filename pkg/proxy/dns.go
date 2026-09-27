// Package proxy provides DNS interception, forwarding, and tunneling neutralization (V-08).
package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/airlock/pkg/audit"
)

// DNSHeader represents the 12-byte header of an RFC 1035 DNS message.
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// DNSServer provides an in-process, localhost DNS forwarder that filters
// hostname resolution requests against the verified domain whitelist (V-08).
type DNSServer struct {
	conn           *net.UDPConn
	port           int
	allowedDomains map[string]bool
	logger         audit.Logger
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	mu             sync.Mutex
	closed         bool
}

// NewDNSServer creates and starts an ephemeral DNS listener on 127.0.0.1:0.
func NewDNSServer(allowedDomains map[string]bool, logger audit.Logger) (*DNSServer, error) {
	if logger == nil {
		logger = &audit.NopLogger{}
	}

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("dns: failed to resolve udp addr: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dns: failed to bind udp listener: %w", err)
	}

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("dns: unexpected non-UDP local address: %T", conn.LocalAddr())
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &DNSServer{
		conn:           conn,
		port:           localAddr.Port,
		allowedDomains: allowedDomains,
		logger:         logger,
		ctx:            ctx,
		cancel:         cancel,
	}

	s.wg.Add(1)
	go s.serve()

	return s, nil
}

// Port returns the ephemeral UDP port assigned to this DNS server.
func (s *DNSServer) Port() int {
	return s.port
}

// Close gracefully terminates the DNS listener.
func (s *DNSServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.cancel()
	err := s.conn.Close()
	s.mu.Unlock()

	s.wg.Wait()
	return err
}

func (s *DNSServer) serve() {
	defer s.wg.Done()

	buf := make([]byte, 1024)
	for {
		n, remoteAddr, err := s.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					time.Sleep(5 * time.Millisecond)
					continue
				}
				return
			}
		}

		if n < 12 {
			continue // Malformed or truncated packet
		}

		query := make([]byte, n)
		copy(query, buf[:n])

		s.wg.Add(1)
		go func(q []byte, rAddr net.Addr) {
			defer s.wg.Done()
			s.handleQuery(q, rAddr)
		}(query, remoteAddr)
	}
}

func (s *DNSServer) handleQuery(query []byte, remoteAddr net.Addr) {
	header := DNSHeader{
		ID:      binary.BigEndian.Uint16(query[0:2]),
		Flags:   binary.BigEndian.Uint16(query[2:4]),
		QDCount: binary.BigEndian.Uint16(query[4:6]),
	}

	// Parse QNAME and QTYPE from question section
	domain, qtype, qnameLen, err := parseQuestion(query[12:])
	if err != nil {
		s.sendError(header.ID, 1, remoteAddr) // Format error
		return
	}

	qtypeStr := "A"
	if qtype == 28 {
		qtypeStr = "AAAA"
	}

	// Policy Check: Verify queried domain against allowed whitelist
	if !s.isDomainAllowed(domain) {
		// Log unauthorized attempt / potential DNS tunneling
		_ = s.logger.LogDNS(audit.DNSRecord{
			Domain:    domain,
			QueryType: qtypeStr,
			Action:    "DENY",
			Reason:    "domain_not_whitelisted",
		})
		// Reply NXDOMAIN (RCODE 3) to neutralize data exfiltration
		s.sendNXDomain(query, header.ID, qnameLen, remoteAddr)
		return
	}

	// Authorized domain: perform host resolution outside sandbox boundary
	ctx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
	if err != nil || len(ips) == 0 {
		s.sendNXDomain(query, header.ID, qnameLen, remoteAddr)
		return
	}

	var resolvedStrs []string
	var targetIPs []net.IP
	for _, ip := range ips {
		resolvedStrs = append(resolvedStrs, ip.String())
		if qtype == 1 && ip.To4() != nil {
			targetIPs = append(targetIPs, ip.To4())
		} else if qtype == 28 && ip.To4() == nil && ip.To16() != nil {
			targetIPs = append(targetIPs, ip.To16())
		}
	}

	_ = s.logger.LogDNS(audit.DNSRecord{
		Domain:      domain,
		QueryType:   qtypeStr,
		Action:      "ALLOW",
		Reason:      "whitelisted_domain",
		ResolvedIPs: resolvedStrs,
	})

	s.sendResponse(query, header.ID, qtype, targetIPs, remoteAddr)
}

func (s *DNSServer) isDomainAllowed(host string) bool {
	hostLower := strings.ToLower(strings.TrimSuffix(host, "."))
	if s.allowedDomains[hostLower] {
		return true
	}

	for allowed := range s.allowedDomains {
		if strings.HasSuffix(hostLower, "."+allowed) {
			return true
		}
	}
	return false
}

func parseQuestion(data []byte) (domain string, qtype uint16, length int, err error) {
	var parts []string
	idx := 0

	for {
		if idx >= len(data) {
			return "", 0, 0, fmt.Errorf("malformed question")
		}
		labelLen := int(data[idx])
		idx++
		if labelLen == 0 {
			break
		}
		if idx+labelLen > len(data) {
			return "", 0, 0, fmt.Errorf("label length out of bounds")
		}
		parts = append(parts, string(data[idx:idx+labelLen]))
		idx += labelLen
	}

	if idx+4 > len(data) {
		return "", 0, 0, fmt.Errorf("question truncated before type and class")
	}

	qtype = binary.BigEndian.Uint16(data[idx : idx+2])
	// data[idx+2 : idx+4] is QCLASS (usually 1 for IN)
	totalQuestionLen := idx + 4

	return strings.Join(parts, "."), qtype, totalQuestionLen, nil
}

func (s *DNSServer) sendNXDomain(query []byte, id uint16, qLen int, remoteAddr net.Addr) {
	resp := make([]byte, 12+qLen)
	binary.BigEndian.PutUint16(resp[0:2], id)
	// Flags: QR=1 (response), AA=1, RD=1, RA=1, RCODE=3 (NXDomain) -> 0x8183
	binary.BigEndian.PutUint16(resp[2:4], 0x8183)
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(resp[6:8], 0) // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)

	copy(resp[12:], query[12:12+qLen])
	_, _ = s.conn.WriteTo(resp, remoteAddr)
}

func (s *DNSServer) sendError(id uint16, rcode uint16, remoteAddr net.Addr) {
	resp := make([]byte, 12)
	binary.BigEndian.PutUint16(resp[0:2], id)
	binary.BigEndian.PutUint16(resp[2:4], 0x8180|(rcode&0x0F))
	_, _ = s.conn.WriteTo(resp, remoteAddr)
}

func (s *DNSServer) sendResponse(query []byte, id uint16, qtype uint16, ips []net.IP, remoteAddr net.Addr) {
	qLen := len(query) - 12
	resp := make([]byte, 12+qLen)

	binary.BigEndian.PutUint16(resp[0:2], id)
	// Flags: QR=1, AA=0, RD=1, RA=1, RCODE=0 (NoError) -> 0x8180
	binary.BigEndian.PutUint16(resp[2:4], 0x8180)
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT

	copy(resp[12:], query[12:])

	anCount := 0
	for _, ip := range ips {
		var rdata []byte
		var rdType uint16
		if qtype == 1 && ip.To4() != nil {
			rdata = ip.To4()
			rdType = 1
		} else if qtype == 28 && ip.To4() == nil && ip.To16() != nil {
			rdata = ip.To16()
			rdType = 28
		} else {
			continue
		}

		// Answer Resource Record:
		// Pointer to question name (0xC00C)
		record := make([]byte, 12+len(rdata))
		binary.BigEndian.PutUint16(record[0:2], 0xC00C) // pointer to QNAME at byte 12
		binary.BigEndian.PutUint16(record[2:4], rdType) // TYPE
		binary.BigEndian.PutUint16(record[4:6], 1)      // CLASS IN
		binary.BigEndian.PutUint32(record[6:10], 60)    // TTL: 60s
		binary.BigEndian.PutUint16(record[10:12], uint16(len(rdata)))
		copy(record[12:], rdata)

		resp = append(resp, record...)
		anCount++
	}

	binary.BigEndian.PutUint16(resp[6:8], uint16(anCount)) // ANCOUNT
	_, _ = s.conn.WriteTo(resp, remoteAddr)
}
