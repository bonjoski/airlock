package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	errBlockedEgressIP = errors.New("proxy: target IP blocked by egress security policy")
	errSNICaptured     = errors.New("proxy: tls clienthello sni captured")
)

var restrictedCIDRs = mustParsePrefixes([]string{
	"0.0.0.0/8",          // RFC 1122 "this host on this network" / unspecified
	"10.0.0.0/8",         // RFC 1918 private
	"100.64.0.0/10",      // RFC 6598 Carrier-Grade NAT (CGNAT / Alibaba IMDS)
	"127.0.0.0/8",        // Loopback
	"169.254.0.0/16",     // Link-local / Cloud IMDS (AWS, GCP, Azure)
	"172.16.0.0/12",      // RFC 1918 private
	"192.0.0.0/24",       // IETF protocol assignments
	"192.168.0.0/16",     // RFC 1918 private
	"198.18.0.0/15",      // Benchmarking
	"224.0.0.0/4",        // IPv4 Multicast
	"240.0.0.0/4",        // Reserved / Broadcast
	"::/128",             // IPv6 Unspecified
	"::1/128",            // IPv6 Loopback
	"64:ff9b::/96",       // RFC 6052 Well-Known NAT64
	"64:ff9b:1::/48",     // RFC 8215 Local-Use NAT64
	"2002::/16",          // 6to4
	"fc00::/7",           // IPv6 Unique Local Address (ULA, includes fd00:ec2::254 AWS IMDS)
	"fe80::/10",          // IPv6 Link-Local
	"ff00::/8",           // IPv6 Multicast
})

func mustParsePrefixes(raw []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			panic("proxy: invalid restricted CIDR " + s + ": " + err.Error())
		}
		out = append(out, p)
	}
	return out
}

// IsBlockedEgressIP checks whether ip belongs to loopback, link-local/IMDS, RFC1918,
// CGNAT, IPv6 ULA, NAT64, multicast, or unspecified address space (AIR-04).
func IsBlockedEgressIP(ip net.IP) (bool, string) {
	if len(ip) == 0 {
		return true, "empty_ip"
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true, "invalid_ip"
	}
	// Unmap IPv4-mapped IPv6 addresses (e.g. ::ffff:169.254.169.254 -> 169.254.169.254)
	addr = addr.Unmap()

	if addr.IsUnspecified() {
		return true, "unspecified"
	}
	if addr.IsLoopback() {
		return true, "loopback"
	}
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return true, "link_local_or_imds"
	}
	if addr.IsMulticast() {
		return true, "multicast"
	}
	for _, p := range restrictedCIDRs {
		if p.Contains(addr) {
			return true, p.String()
		}
	}
	return false, ""
}

// newSafeDialer returns a net.Dialer that enforces socket-level IP validation via
// Control right before connect(2), eliminating DNS rebinding TOCTOU windows (AIR-04).
func newSafeDialer(timeout time.Duration, allowPrivateForTest bool) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			if allowPrivateForTest {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("%w: malformed dial address %q: %w", errBlockedEgressIP, address, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("%w: non-IP dial address %q", errBlockedEgressIP, host)
			}
			if blocked, reason := IsBlockedEgressIP(ip); blocked {
				return fmt.Errorf("%w: %s (%s)", errBlockedEgressIP, ip.String(), reason)
			}
			return nil
		},
	}
}

// splitHostPortDefault parses host and port using net.SplitHostPort, handling IPv6
// bracketed literals cleanly and applying defaultPort when no explicit port is present.
func splitHostPortDefault(target string, defaultPort int) (string, int, error) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return "", 0, errors.New("empty host")
	}

	if host, portStr, err := net.SplitHostPort(trimmed); err == nil {
		if host == "" {
			return "", 0, errors.New("empty host in host:port")
		}
		pVal, convErr := strconv.Atoi(portStr)
		if convErr != nil || pVal <= 0 || pVal > 65535 {
			return "", 0, fmt.Errorf("invalid port %q", portStr)
		}
		return strings.TrimSuffix(strings.ToLower(host), "."), pVal, nil
	}

	// Handle bare IPv6 literal in brackets without port, e.g. "[::1]"
	if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
		inner := trimmed[1 : len(trimmed)-1]
		if net.ParseIP(inner) == nil {
			return "", 0, fmt.Errorf("invalid bracketed IPv6 host %q", trimmed)
		}
		return strings.ToLower(inner), defaultPort, nil
	}

	// Reject malformed unbracketed colons
	if strings.Contains(trimmed, ":") {
		return "", 0, fmt.Errorf("malformed host:port %q", trimmed)
	}

	return strings.TrimSuffix(strings.ToLower(trimmed), "."), defaultPort, nil
}

type clientHelloPeekConn struct {
	reader   io.Reader
	recorded bytes.Buffer
	maxBytes int
}

func (c *clientHelloPeekConn) Read(b []byte) (int, error) {
	if c.recorded.Len() >= c.maxBytes {
		return 0, errors.New("tls clienthello exceeded maximum size")
	}
	rem := c.maxBytes - c.recorded.Len()
	if len(b) > rem {
		b = b[:rem]
	}
	n, err := c.reader.Read(b)
	if n > 0 {
		_, _ = c.recorded.Write(b[:n])
	}
	return n, err
}

func (c *clientHelloPeekConn) Write(b []byte) (int, error) {
	// Discard any TLS alerts so raw client socket is never polluted
	return len(b), nil
}

func (c *clientHelloPeekConn) Close() error                       { return nil }
func (c *clientHelloPeekConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *clientHelloPeekConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *clientHelloPeekConn) SetDeadline(t time.Time) error      { return nil }
func (c *clientHelloPeekConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *clientHelloPeekConn) SetWriteDeadline(t time.Time) error { return nil }

// peekTLSClientHelloSNI inspects the initial TLS ClientHello from reader without
// consuming bytes permanently (returning the exact bytes read so they can be replayed
// to the upstream server after SNI validation succeeds) (AIR-04).
func peekTLSClientHelloSNI(client net.Conn, reader *bufio.Reader) (string, []byte, error) {
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer func() {
		_ = client.SetReadDeadline(time.Time{})
	}()

	peekConn := &clientHelloPeekConn{
		reader:   reader,
		maxBytes: 32 * 1024,
	}

	var sni string
	tlsSrv := tls.Server(peekConn, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hello.ServerName)), ".")
			return nil, errSNICaptured
		},
	})

	err := tlsSrv.Handshake()
	if !errors.Is(err, errSNICaptured) {
		if err == nil {
			return "", nil, errors.New("unexpected tls handshake completion during sni peek")
		}
		return "", nil, fmt.Errorf("invalid tls clienthello: %w", err)
	}

	return sni, peekConn.recorded.Bytes(), nil
}

type boundedHeaderReader struct {
	r         io.Reader
	limit     int64
	remaining int64
	active    bool
}

func newBoundedHeaderReader(r io.Reader, limit int64) *boundedHeaderReader {
	return &boundedHeaderReader{
		r:         r,
		limit:     limit,
		remaining: limit,
		active:    true,
	}
}

func (b *boundedHeaderReader) reset() {
	b.remaining = b.limit
	b.active = true
}

func (b *boundedHeaderReader) disable() {
	b.active = false
}

func (b *boundedHeaderReader) Read(p []byte) (int, error) {
	if b.active {
		if b.remaining <= 0 {
			return 0, errors.New("proxy: http request header exceeded maximum allowed size")
		}
		if int64(len(p)) > b.remaining {
			p = p[:b.remaining]
		}
	}
	n, err := b.r.Read(p)
	if b.active && n > 0 {
		b.remaining -= int64(n)
	}
	return n, err
}
