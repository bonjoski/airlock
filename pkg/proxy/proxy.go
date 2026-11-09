// Package proxy provides an in-process, lightweight HTTP/HTTPS forward proxy
// that filters outbound requests against verified package registry domains (V-02/V-08).
package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/airlock/pkg/audit"
	"github.com/bonjoski/airlock/pkg/config"
	"github.com/bonjoski/airlock/pkg/interactive"
)

// DefaultAllowedRegistries defines verified package manager registry endpoints.
var DefaultAllowedRegistries = []string{
	"registry.npmjs.org",
	"registry.yarnpkg.com",
	"pypi.org",
	"files.pythonhosted.org",
	"crates.io",
	"static.crates.io",
	"index.crates.io",
	"rubygems.org",
}

// PromptHandler callback for interactive runtime permission prompts.
type PromptHandler func(domain string) interactive.Grant

// Proxy defines the interface for an ephemeral egress forward proxy with DNS support.
type Proxy interface {
	Port() int
	DNSPort() int
	URL() string
	Close() error
}

// Options specifies configuration options for the egress forward proxy.
type Options struct {
	AllowedDomains          []string
	AllowedConnectPorts     []int
	AllowPrivateIPsForTests bool
	Logger                  audit.Logger
	PromptHandler           PromptHandler
	ConfigPath              string
}

// EgressProxy implements an ephemeral localhost forward proxy with domain whitelisting and DNS interception.
type EgressProxy struct {
	listener            net.Listener
	port                int
	dnsServer           *DNSServer
	allowedDomains      map[string]bool
	domainRules         []string
	allowedConnectPorts map[int]bool
	allowPrivateForTest bool
	dialer              *net.Dialer
	httpTransport       *http.Transport
	domainMu            sync.RWMutex
	promptHandler       PromptHandler
	configPath          string
	logger              audit.Logger
	ctx                 context.Context
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
	mu                  sync.Mutex
	closed              bool
}

// New creates and starts an ephemeral forward proxy on an unprivileged localhost port.
func New(extraAllowedDomains []string) (*EgressProxy, error) {
	return NewWithLogger(extraAllowedDomains, &audit.NopLogger{})
}

// NewWithLogger creates an ephemeral forward proxy with structured audit telemetry.
func NewWithLogger(extraAllowedDomains []string, logger audit.Logger) (*EgressProxy, error) {
	return NewWithOptions(Options{
		AllowedDomains: extraAllowedDomains,
		Logger:         logger,
	})
}

// NewWithOptions creates an ephemeral forward proxy with full options (prompter, configPath, logger).
func NewWithOptions(opts Options) (*EgressProxy, error) {
	if opts.Logger == nil {
		opts.Logger = &audit.NopLogger{}
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("proxy: failed to bind localhost listener: %w", err)
	}

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return nil, fmt.Errorf("proxy: unexpected non-TCP listener address: %T", listener.Addr())
	}

	allowed := make(map[string]bool, len(DefaultAllowedRegistries)+len(opts.AllowedDomains))
	var rules []string

	for _, domain := range DefaultAllowedRegistries {
		lower := strings.ToLower(domain)
		allowed[lower] = true
		rules = append(rules, lower)
	}
	for _, domain := range opts.AllowedDomains {
		if trimmed := strings.ToLower(strings.TrimSpace(domain)); trimmed != "" {
			allowed[trimmed] = true
			rules = append(rules, trimmed)
		}
	}

	dnsServer, err := NewDNSServerWithOptions(DNSOptions{
		AllowedDomains:          allowed,
		DomainRules:             rules,
		AllowPrivateIPsForTests: opts.AllowPrivateIPsForTests,
		Logger:                  opts.Logger,
		PromptHandler:           opts.PromptHandler,
		ConfigPath:              opts.ConfigPath,
	})
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("proxy: failed to start dns forwarder: %w", err)
	}

	connectPorts := make(map[int]bool)
	if len(opts.AllowedConnectPorts) == 0 {
		connectPorts[443] = true
	} else {
		for _, cp := range opts.AllowedConnectPorts {
			if cp > 0 && cp <= 65535 {
				connectPorts[cp] = true
			}
		}
	}

	safeDialer := newSafeDialer(10*time.Second, opts.AllowPrivateIPsForTests)
	transport := &http.Transport{
		DialContext:           safeDialer.DialContext,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          32,
		DisableCompression:    true,
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &EgressProxy{
		listener:            listener,
		port:                tcpAddr.Port,
		dnsServer:           dnsServer,
		allowedDomains:      allowed,
		domainRules:         rules,
		allowedConnectPorts: connectPorts,
		allowPrivateForTest: opts.AllowPrivateIPsForTests,
		dialer:              safeDialer,
		httpTransport:       transport,
		promptHandler:       opts.PromptHandler,
		configPath:          opts.ConfigPath,
		logger:              opts.Logger,
		ctx:                 ctx,
		cancel:              cancel,
	}

	p.wg.Add(1)
	go p.serve()

	return p, nil
}

// Port returns the assigned localhost HTTP proxy port.
func (p *EgressProxy) Port() int {
	return p.port
}

// DNSPort returns the assigned localhost DNS interceptor port.
func (p *EgressProxy) DNSPort() int {
	if p.dnsServer != nil {
		return p.dnsServer.Port()
	}
	return 0
}

// URL returns the proxy address formatted for HTTP_PROXY / HTTPS_PROXY.
func (p *EgressProxy) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", p.port)
}

// Close gracefully terminates the proxy listener, DNS forwarder, and waits for active connections.
func (p *EgressProxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.cancel()
	err := p.listener.Close()
	p.mu.Unlock()

	if p.dnsServer != nil {
		_ = p.dnsServer.Close()
	}
	if p.httpTransport != nil {
		p.httpTransport.CloseIdleConnections()
	}

	p.wg.Wait()
	return err
}

func (p *EgressProxy) serve() {
	defer p.wg.Done()

	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return
			default:
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					time.Sleep(5 * time.Millisecond)
					continue
				}
				return
			}
		}

		p.wg.Add(1)
		go func(c net.Conn) {
			defer p.wg.Done()
			p.handleConnection(c)
		}(conn)
	}
}

const (
	maxProxyHeaderBytes = 64 * 1024
	maxProxyBodyBytes   = 64 * 1024 * 1024
)

func (p *EgressProxy) handleConnection(client net.Conn) {
	defer client.Close()

	_ = client.SetDeadline(time.Now().Add(15 * time.Second))
	hdrGuard := newBoundedHeaderReader(client, maxProxyHeaderBytes)
	reader := bufio.NewReader(hdrGuard)
	clientAddr := client.RemoteAddr().String()

	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	hdrGuard.disable()

	if req.Method == http.MethodConnect {
		p.handleConnect(client, reader, req, clientAddr)
		return
	}

	// Plain HTTP forwarding: parse and validate EVERY request on the connection (AIR-04)
	p.handlePlainHTTP(client, reader, hdrGuard, req, clientAddr)
}

func (p *EgressProxy) handleConnect(client net.Conn, reader *bufio.Reader, req *http.Request, clientAddr string) {
	rawTarget := req.Host
	if rawTarget == "" && req.URL != nil {
		rawTarget = req.URL.Host
	}

	host, port, err := splitHostPortDefault(rawTarget, 443)
	if err != nil || host == "" {
		_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	// Enforce allowed CONNECT ports (443 by default) (AIR-04)
	if !p.allowedConnectPorts[port] {
		_ = p.logger.LogNetwork(audit.NetworkRecord{
			Protocol:   "https_connect",
			Host:       host,
			Port:       port,
			Action:     "DENY",
			Reason:     "connect_port_not_allowed",
			ClientAddr: clientAddr,
		})
		_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nBlocked by Airlock Sandbox: CONNECT port not permitted.\r\n"))
		return
	}

	// Reject literal private/loopback/IMDS IP targets immediately (AIR-04)
	if ip := net.ParseIP(host); ip != nil && !p.allowPrivateForTest {
		if blocked, reason := IsBlockedEgressIP(ip); blocked {
			_ = p.logger.LogNetwork(audit.NetworkRecord{
				Protocol:   "https_connect",
				Host:       host,
				Port:       port,
				Action:     "DENY",
				Reason:     "blocked_ip_" + reason,
				ClientAddr: clientAddr,
			})
			_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nBlocked by Airlock Sandbox: Restricted target IP.\r\n"))
			return
		}
	}

	// Verify target host against allowed domain whitelist & wildcard rules
	if !p.isDomainAllowed(host) {
		_ = p.logger.LogNetwork(audit.NetworkRecord{
			Protocol:   "https_connect",
			Host:       host,
			Port:       port,
			Action:     "DENY",
			Reason:     "domain_not_whitelisted",
			ClientAddr: clientAddr,
		})
		_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nBlocked by Airlock Sandbox: Target domain not whitelisted.\r\n"))
		return
	}

	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
	dialCtx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
	remote, err := p.dialer.DialContext(dialCtx, "tcp", targetAddr)
	cancel()
	if err != nil {
		if errors.Is(err, errBlockedEgressIP) {
			_ = p.logger.LogNetwork(audit.NetworkRecord{
				Protocol:   "https_connect",
				Host:       host,
				Port:       port,
				Action:     "DENY",
				Reason:     "dns_rebinding_or_restricted_ip",
				ClientAddr: clientAddr,
			})
			_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nBlocked by Airlock Sandbox: Target resolved to restricted IP.\r\n"))
			return
		}
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	// 200 Connection Established
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Peek TLS ClientHello SNI and verify it matches the authorized CONNECT host (AIR-04)
	sni, helloBytes, err := peekTLSClientHelloSNI(client, reader)
	if err != nil {
		_ = p.logger.LogNetwork(audit.NetworkRecord{
			Protocol:   "https_connect",
			Host:       host,
			Port:       port,
			Action:     "DENY",
			Reason:     "invalid_tls_clienthello",
			ClientAddr: clientAddr,
		})
		return
	}

	isLiteralIP := net.ParseIP(host) != nil
	if (!isLiteralIP && !strings.EqualFold(sni, host)) || (isLiteralIP && sni != "" && !strings.EqualFold(sni, host)) {
		_ = p.logger.LogNetwork(audit.NetworkRecord{
			Protocol:   "https_connect",
			Host:       host,
			Port:       port,
			Action:     "DENY",
			Reason:     "tls_sni_mismatch",
			ClientAddr: clientAddr,
		})
		return
	}

	_ = p.logger.LogNetwork(audit.NetworkRecord{
		Protocol:   "https_connect",
		Host:       host,
		Port:       port,
		Action:     "ALLOW",
		Reason:     "whitelisted_domain",
		ClientAddr: clientAddr,
	})

	// Reset deadlines and replay validated ClientHello to upstream
	_ = client.SetDeadline(time.Time{})
	_ = remote.SetDeadline(time.Time{})
	if len(helloBytes) > 0 {
		if _, err := remote.Write(helloBytes); err != nil {
			return
		}
	}

	p.pipe(client, remote, reader)
}

func (p *EgressProxy) handlePlainHTTP(client net.Conn, reader *bufio.Reader, hdrGuard *boundedHeaderReader, firstReq *http.Request, clientAddr string) {
	req := firstReq
	for {
		if req.Body != nil {
			req.Body = http.MaxBytesReader(nil, req.Body, maxProxyBodyBytes)
		}

		if !p.forwardSingleHTTPRequest(client, req, clientAddr) {
			return
		}
		if req.Close {
			return
		}

		// Parse the next Keep-Alive HTTP request independently so Host smuggling is impossible (AIR-04)
		_ = client.SetDeadline(time.Now().Add(15 * time.Second))
		hdrGuard.reset()
		nextReq, err := http.ReadRequest(reader)
		hdrGuard.disable()
		if err != nil {
			return
		}
		req = nextReq
	}
}

func (p *EgressProxy) forwardSingleHTTPRequest(client net.Conn, req *http.Request, clientAddr string) bool {
	if req.URL == nil {
		_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
		return false
	}
	if req.URL.Scheme != "" && !strings.EqualFold(req.URL.Scheme, "http") {
		_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
		return false
	}

	rawURLHost := strings.TrimSpace(req.URL.Host)
	rawHdrHost := strings.TrimSpace(req.Host)
	if rawURLHost == "" && rawHdrHost == "" {
		_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
		return false
	}

	var host string
	var port int
	if rawURLHost != "" {
		h, pt, err := splitHostPortDefault(rawURLHost, 80)
		if err != nil {
			_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
			return false
		}
		host, port = h, pt
	}
	if rawHdrHost != "" {
		hdrH, hdrPt, err := splitHostPortDefault(rawHdrHost, 80)
		if err != nil {
			_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
			return false
		}
		// Reject mismatched absolute-URI host vs Host header smuggling (AIR-04)
		if host != "" && (!strings.EqualFold(host, hdrH) || port != hdrPt) {
			_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
			return false
		}
		host, port = hdrH, hdrPt
	}

	if ip := net.ParseIP(host); ip != nil && !p.allowPrivateForTest {
		if blocked, reason := IsBlockedEgressIP(ip); blocked {
			_ = p.logger.LogNetwork(audit.NetworkRecord{
				Protocol:   "http_plain",
				Host:       host,
				Port:       port,
				Action:     "DENY",
				Reason:     "blocked_ip_" + reason,
				ClientAddr: clientAddr,
			})
			_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nBlocked by Airlock Sandbox: Restricted target IP.\r\n"))
			return false
		}
	}

	if !p.isDomainAllowed(host) {
		_ = p.logger.LogNetwork(audit.NetworkRecord{
			Protocol:   "http_plain",
			Host:       host,
			Port:       port,
			Action:     "DENY",
			Reason:     "domain_not_whitelisted",
			ClientAddr: clientAddr,
		})
		_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nBlocked by Airlock Sandbox: Target domain not whitelisted.\r\n"))
		return false
	}

	targetHostPort := net.JoinHostPort(host, strconv.Itoa(port))
	outReq := req.Clone(p.ctx)
	outReq.RequestURI = ""
	outReq.URL.Scheme = "http"
	outReq.URL.Host = targetHostPort
	outReq.Host = targetHostPort
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authorization")

	resp, err := p.httpTransport.RoundTrip(outReq)
	if err != nil {
		if errors.Is(err, errBlockedEgressIP) {
			_ = p.logger.LogNetwork(audit.NetworkRecord{
				Protocol:   "http_plain",
				Host:       host,
				Port:       port,
				Action:     "DENY",
				Reason:     "dns_rebinding_or_restricted_ip",
				ClientAddr: clientAddr,
			})
			_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nBlocked by Airlock Sandbox: Target resolved to restricted IP.\r\n"))
			return false
		}
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"))
		return false
	}
	defer resp.Body.Close()

	_ = p.logger.LogNetwork(audit.NetworkRecord{
		Protocol:   "http_plain",
		Host:       host,
		Port:       port,
		Action:     "ALLOW",
		Reason:     "whitelisted_domain",
		ClientAddr: clientAddr,
	})

	_ = client.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err := resp.Write(client); err != nil {
		return false
	}
	return !resp.Close
}

func (p *EgressProxy) pipe(client, remote net.Conn, reader *bufio.Reader) {
	var pipeWg sync.WaitGroup
	pipeWg.Add(2)

	go func() {
		defer pipeWg.Done()
		_, _ = io.Copy(remote, reader)
		if tc, ok := remote.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer pipeWg.Done()
		_, _ = io.Copy(client, remote)
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	pipeWg.Wait()
}

func (p *EgressProxy) isDomainAllowed(host string) bool {
	hostLower := strings.ToLower(strings.TrimSuffix(host, "."))

	p.domainMu.RLock()
	if p.allowedDomains[hostLower] {
		p.domainMu.RUnlock()
		return true
	}

	for _, rule := range p.domainRules {
		if config.MatchDomain(rule, hostLower) {
			p.domainMu.RUnlock()
			return true
		}
	}
	p.domainMu.RUnlock()

	// Dynamic capability grant prompt
	if p.promptHandler != nil {
		grant := p.promptHandler(hostLower)
		switch grant {
		case interactive.GrantOnce:
			return true
		case interactive.GrantSession:
			p.domainMu.Lock()
			p.allowedDomains[hostLower] = true
			p.domainRules = append(p.domainRules, hostLower)
			if p.dnsServer != nil {
				p.dnsServer.AddAllowedDomain(hostLower)
			}
			p.domainMu.Unlock()
			return true
		case interactive.GrantPersist:
			p.domainMu.Lock()
			p.allowedDomains[hostLower] = true
			p.domainRules = append(p.domainRules, hostLower)
			if p.dnsServer != nil {
				p.dnsServer.AddAllowedDomain(hostLower)
			}
			p.domainMu.Unlock()
			if p.configPath != "" {
				_ = config.AppendAllowedDomain(p.configPath, hostLower)
			}
			return true
		}
	}

	return false
}
