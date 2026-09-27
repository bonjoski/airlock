// Package proxy provides an in-process, lightweight HTTP/HTTPS forward proxy
// that filters outbound requests against verified package registry domains (V-02/V-08).
package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
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

// Proxy defines the interface for an ephemeral egress forward proxy.
type Proxy interface {
	Port() int
	URL() string
	Close() error
}

// EgressProxy implements an ephemeral localhost forward proxy with domain whitelisting.
type EgressProxy struct {
	listener       net.Listener
	port           int
	allowedDomains map[string]bool
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	mu             sync.Mutex
	closed         bool
}

// New creates and starts an ephemeral forward proxy on an unprivileged localhost port.
func New(extraAllowedDomains []string) (*EgressProxy, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("proxy: failed to bind localhost listener: %w", err)
	}

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return nil, fmt.Errorf("proxy: unexpected non-TCP listener address: %T", listener.Addr())
	}

	allowed := make(map[string]bool, len(DefaultAllowedRegistries)+len(extraAllowedDomains))
	for _, domain := range DefaultAllowedRegistries {
		allowed[strings.ToLower(domain)] = true
	}
	for _, domain := range extraAllowedDomains {
		allowed[strings.ToLower(strings.TrimSpace(domain))] = true
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &EgressProxy{
		listener:       listener,
		port:           tcpAddr.Port,
		allowedDomains: allowed,
		ctx:            ctx,
		cancel:         cancel,
	}

	p.wg.Add(1)
	go p.serve()

	return p, nil
}

// Port returns the assigned localhost port.
func (p *EgressProxy) Port() int {
	return p.port
}

// URL returns the proxy address formatted for HTTP_PROXY / HTTPS_PROXY.
func (p *EgressProxy) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", p.port)
}

// Close gracefully terminates the proxy listener and waits for active connections.
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

	if !strings.HasPrefix(line, "CONNECT ") {
		// Reject plain HTTP or non-CONNECT methods
		_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\nOnly CONNECT tunneling to verified package registries is supported by Airlock.\r\n"))
		return
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}

	target := parts[1]
	host := target
	if colonIdx := strings.Index(target, ":"); colonIdx != -1 {
		host = target[:colonIdx]
	}

	// Drain headers until empty line
	for {
		headerLine, err := reader.ReadString('\n')
		if err != nil || headerLine == "\r\n" || headerLine == "\n" {
			break
		}
	}

	// Verify target host against allowed domain whitelist
	if !p.isDomainAllowed(host) {
		_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nBlocked by Airlock Sandbox: Target domain not whitelisted.\r\n"))
		return
	}

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

	// Clear deadlines for tunnel streaming
	_ = client.SetDeadline(time.Time{})
	_ = remote.SetDeadline(time.Time{})

	// Reply 200 Connection Established
	_, err = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	// Bidirectional byte pipe
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
	hostLower := strings.ToLower(host)
	if p.allowedDomains[hostLower] {
		return true
	}

	// Subdomain matching (e.g. *.npmjs.org)
	for allowed := range p.allowedDomains {
		if strings.HasSuffix(hostLower, "."+allowed) {
			return true
		}
	}

	return false
}
