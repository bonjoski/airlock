// Package proxy provides an in-process, lightweight HTTP/HTTPS forward proxy
// that filters outbound requests against verified package registry domains (V-02/V-08).
package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
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
	AllowedDomains []string
	Logger         audit.Logger
	PromptHandler  PromptHandler
	ConfigPath     string
}

// EgressProxy implements an ephemeral localhost forward proxy with domain whitelisting and DNS interception.
type EgressProxy struct {
	listener       net.Listener
	port           int
	dnsServer      *DNSServer
	allowedDomains map[string]bool
	domainRules    []string
	domainMu       sync.RWMutex
	promptHandler  PromptHandler
	configPath     string
	logger         audit.Logger
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	mu             sync.Mutex
	closed         bool
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
		AllowedDomains: allowed,
		DomainRules:    rules,
		Logger:         opts.Logger,
		PromptHandler:  opts.PromptHandler,
		ConfigPath:     opts.ConfigPath,
	})
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("proxy: failed to start dns forwarder: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &EgressProxy{
		listener:       listener,
		port:           tcpAddr.Port,
		dnsServer:      dnsServer,
		allowedDomains: allowed,
		domainRules:    rules,
		promptHandler:  opts.PromptHandler,
		configPath:     opts.ConfigPath,
		logger:         opts.Logger,
		ctx:            ctx,
		cancel:         cancel,
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

func (p *EgressProxy) handleConnection(client net.Conn) {
	defer client.Close()

	_ = client.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(client)

	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}

	method := parts[0]
	clientAddr := client.RemoteAddr().String()

	if method == "CONNECT" {
		p.handleConnect(client, reader, parts[1], clientAddr)
		return
	}

	// Plain HTTP forwarding (GET, POST, HEAD, PUT, DELETE, OPTIONS)
	p.handlePlainHTTP(client, reader, line, parts, clientAddr)
}

func (p *EgressProxy) handleConnect(client net.Conn, reader *bufio.Reader, target string, clientAddr string) {
	host := target
	port := 443
	if colonIdx := strings.Index(target, ":"); colonIdx != -1 {
		host = target[:colonIdx]
		if pVal, err := strconv.Atoi(target[colonIdx+1:]); err == nil {
			port = pVal
		}
	}

	// Drain headers until empty line
	for {
		headerLine, err := reader.ReadString('\n')
		if err != nil || headerLine == "\r\n" || headerLine == "\n" {
			break
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

	_ = p.logger.LogNetwork(audit.NetworkRecord{
		Protocol:   "https_connect",
		Host:       host,
		Port:       port,
		Action:     "ALLOW",
		Reason:     "whitelisted_domain",
		ClientAddr: clientAddr,
	})

	targetAddr := target
	if !strings.Contains(targetAddr, ":") {
		targetAddr = targetAddr + ":443"
	}

	remote, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	// 200 Connection Established
	_, err = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	// Reset deadlines for bi-directional TLS tunnel
	_ = client.SetDeadline(time.Time{})
	_ = remote.SetDeadline(time.Time{})

	p.pipe(client, remote, reader)
}

func (p *EgressProxy) handlePlainHTTP(client net.Conn, reader *bufio.Reader, firstLine string, parts []string, clientAddr string) {
	reqURL, err := url.Parse(parts[1])
	if err != nil || reqURL.Host == "" {
		_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	host := reqURL.Hostname()
	port := 80
	if reqURL.Port() != "" {
		if pVal, err := strconv.Atoi(reqURL.Port()); err == nil {
			port = pVal
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
		_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nBlocked by Airlock Sandbox: Target domain not whitelisted.\r\n"))
		return
	}

	_ = p.logger.LogNetwork(audit.NetworkRecord{
		Protocol:   "http_plain",
		Host:       host,
		Port:       port,
		Action:     "ALLOW",
		Reason:     "whitelisted_domain",
		ClientAddr: clientAddr,
	})

	targetAddr := reqURL.Host
	if !strings.Contains(targetAddr, ":") {
		targetAddr = targetAddr + ":80"
	}

	remote, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	// Forward the first line
	pathAndQuery := reqURL.RequestURI()
	if pathAndQuery == "" {
		pathAndQuery = "/"
	}
	modifiedFirstLine := fmt.Sprintf("%s %s %s\r\n", parts[0], pathAndQuery, parts[2])
	if _, err := remote.Write([]byte(modifiedFirstLine)); err != nil {
		return
	}

	// Forward the remaining headers
	for {
		headerLine, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if _, err := remote.Write([]byte(headerLine)); err != nil {
			return
		}
		if headerLine == "\r\n" || headerLine == "\n" {
			break
		}
	}

	// Reset deadlines for tunneling data
	_ = client.SetDeadline(time.Time{})
	_ = remote.SetDeadline(time.Time{})

	p.pipe(client, remote, reader)
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
