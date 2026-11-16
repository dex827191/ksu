package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

type Config struct {
	Mode                    string `json:"mode"` // ssh_only, ssh_proxy, ssh_sni, ssh_proxy_payload, ssh_payload_sni, ssh_proxy_payload_sni
	SSHHost                 string `json:"ssh_host"`
	SSHPort                 int    `json:"ssh_port"`
	Username                string `json:"username"`
	Password                string `json:"password"`
	PrivateKey              string `json:"private_key,omitempty"` // PEM text; preferred over password when present
	HostKeyPolicy           string `json:"host_key_policy"`       // strict or insecure (default strict)
	KnownHostsFile          string `json:"known_hosts_file"`
	ProxyHost               string `json:"proxy_host,omitempty"`
	ProxyPort               int    `json:"proxy_port,omitempty"`
	ProxyUsername           string `json:"proxy_username,omitempty"`
	ProxyPassword           string `json:"proxy_password,omitempty"`
	TLSServerName           string `json:"tls_server_name,omitempty"`
	TLSVersion              string `json:"tls_version,omitempty"`
	Payload                 string `json:"payload,omitempty"`
	PayloadMode             string `json:"payload_mode,omitempty"` // normal or enhanced
	LocalSocksHost          string `json:"local_socks_host"`
	LocalSocksPort          int    `json:"local_socks_port"`
	ConnectTimeoutSeconds   int    `json:"connect_timeout_seconds"`
	KeepAliveSeconds        int    `json:"keepalive_seconds"`
	SocketSendBufferSize    int    `json:"socket_send_buffer_size"`
	SocketReceiveBufferSize int    `json:"socket_receive_buffer_size"`
	TCPNoDelay              bool   `json:"tcp_no_delay"`
	ReadTimeoutSeconds      int    `json:"read_timeout_seconds"`
	LogFile                 string `json:"log_file"`
	AutoReconnect           bool   `json:"auto_reconnect"`
	MaxReconnect            int    `json:"max_reconnect"`
}

func defaults(c *Config) {
	if c.Mode == "" {
		c.Mode = "ssh_only"
	}
	if c.SSHPort == 0 {
		c.SSHPort = 22
	}
	if c.LocalSocksHost == "" {
		c.LocalSocksHost = "127.0.0.1"
	}
	if c.LocalSocksPort == 0 {
		c.LocalSocksPort = 10808
	}
	if c.ConnectTimeoutSeconds == 0 {
		c.ConnectTimeoutSeconds = 15
	}
	if c.KeepAliveSeconds == 0 {
		c.KeepAliveSeconds = 30
	}
	if c.SocketSendBufferSize == 0 {
		c.SocketSendBufferSize = 16384
	}
	if c.SocketReceiveBufferSize == 0 {
		c.SocketReceiveBufferSize = 32768
	}
	if c.HostKeyPolicy == "" {
		c.HostKeyPolicy = "strict"
	}
	if c.KnownHostsFile == "" {
		c.KnownHostsFile = "/data/adb/sshprotocol/known_hosts"
	}
	if c.LogFile == "" {
		c.LogFile = "/data/adb/sshprotocol/logs/sshprotocol.log"
	}
}

func loadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	defaults(&c)
	return c, err
}

func logger(path string) (*log.Logger, func()) {
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return log.New(os.Stderr, "", log.LstdFlags), func() {}
	}
	return log.New(f, "", log.LstdFlags), func() { _ = f.Close() }
}

func hostKeyCallback(c Config) (ssh.HostKeyCallback, error) {
	if c.HostKeyPolicy == "insecure" {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	if c.HostKeyPolicy != "strict" {
		return nil, fmt.Errorf("host_key_policy must be strict or insecure")
	}
	_ = os.MkdirAll(filepath.Dir(c.KnownHostsFile), 0700)
	f, err := os.OpenFile(c.KnownHostsFile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	return knownHostsCallback(c.KnownHostsFile)
}

// Small known_hosts reader: accepts OpenSSH "host keytype base64" lines.
// Unknown hosts fail closed; add the server key to known_hosts manually.
func knownHostsCallback(path string) (ssh.HostKeyCallback, error) {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		host := hostname
		if h, port, e := net.SplitHostPort(hostname); e == nil {
			if port == "22" {
				host = h
			} else {
				host = "[" + h + "]:" + port
			}
		}
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || strings.HasPrefix(fields[0], "#") {
				continue
			}
			for _, h := range strings.Split(fields[0], ",") {
				if h == host || h == hostname {
					blob, e := base64.StdEncoding.DecodeString(fields[2])
					if e == nil && fields[1] == key.Type() && string(blob) == string(key.Marshal()) {
						return nil
					}
				}
			}
		}
		return fmt.Errorf("SSH host key for %s is not trusted; add its key to %s", hostname, path)
	}, nil
}

func dialMarked(c Config, address string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	d.Control = func(network, address string, raw syscall.RawConn) error {
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			// SO_MARK (Linux/Android) routes SSH transport outside the TUN policy table.
			sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 36, 438)
			if sockErr == nil && c.TCPNoDelay {
				sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
			}
			if sockErr == nil && c.SocketSendBufferSize > 0 {
				sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, c.SocketSendBufferSize)
			}
			if sockErr == nil && c.SocketReceiveBufferSize > 0 {
				sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, c.SocketReceiveBufferSize)
			}
		}); err != nil {
			return err
		}
		return sockErr
	}
	return d.Dial("tcp", address)
}

func dialUpstream(c Config) (net.Conn, error) {
	timeout := time.Duration(c.ConnectTimeoutSeconds) * time.Second
	mode := c.Mode
	useProxy := strings.Contains(mode, "proxy")
	usePayload := strings.Contains(mode, "payload")
	useTLS := strings.Contains(mode, "sni")
	target := net.JoinHostPort(c.SSHHost, strconv.Itoa(c.SSHPort))

	dialHost, dialPort := c.SSHHost, c.SSHPort
	if useProxy {
		if c.ProxyHost == "" || c.ProxyPort < 1 || c.ProxyPort > 65535 {
			return nil, errors.New("proxy mode requires valid proxy_host and proxy_port")
		}
		dialHost, dialPort = c.ProxyHost, c.ProxyPort
	}
	conn, err := dialMarked(c, net.JoinHostPort(dialHost, strconv.Itoa(dialPort)), timeout)
	if err != nil {
		return nil, err
	}

	// The original app sends HTTP CONNECT only for SSH_PROXY (without custom payload).
	// With payload enabled, the proxy receives the user's payload directly.
	if useProxy && !usePayload {
		req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\nProxy-Connection: Keep-Alive\r\n"
		if c.ProxyUsername != "" {
			token := base64.StdEncoding.EncodeToString([]byte(c.ProxyUsername + ":" + c.ProxyPassword))
			req += "Proxy-Authorization: Basic " + token + "\r\n"
		}
		if _, err = io.WriteString(conn, req+"\r\n"); err != nil {
			conn.Close()
			return nil, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		br := bufio.NewReader(conn)
		status, e := br.ReadString('\n')
		if e != nil {
			conn.Close()
			return nil, fmt.Errorf("HTTP CONNECT status: %w", e)
		}
		fields := strings.Fields(status)
		if len(fields) < 2 || fields[1] != "200" {
			conn.Close()
			return nil, fmt.Errorf("HTTP proxy rejected CONNECT: %s", strings.TrimSpace(status))
		}
		headerBytes := len(status)
		for {
			line, e := br.ReadString('\n')
			if e != nil {
				conn.Close()
				return nil, fmt.Errorf("HTTP CONNECT headers: %w", e)
			}
			headerBytes += len(line)
			if headerBytes > 32768 {
				conn.Close()
				return nil, errors.New("HTTP CONNECT response headers too large")
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		if br.Buffered() > 0 {
			conn = &bufferedConn{Conn: conn, r: br}
		}
		_ = conn.SetReadDeadline(time.Time{})
	}

	// TLS is applied after TCP/CONNECT and before the payload, matching the app pipeline.
	if useTLS {
		if strings.TrimSpace(c.TLSServerName) == "" {
			conn.Close()
			return nil, errors.New("TLS/SNI mode requires tls_server_name")
		}
		tlsConfig := &tls.Config{ServerName: c.TLSServerName, MinVersion: tls.VersionTLS12}
		switch c.TLSVersion {
		case "", "default", "tls_1_2":
			tlsConfig.MinVersion = tls.VersionTLS12
		case "tls_1_0":
			tlsConfig.MinVersion, tlsConfig.MaxVersion = tls.VersionTLS10, tls.VersionTLS10
		case "tls_1_1":
			tlsConfig.MinVersion, tlsConfig.MaxVersion = tls.VersionTLS11, tls.VersionTLS11
		case "tls_1_3":
			tlsConfig.MinVersion, tlsConfig.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
		default:
			conn.Close()
			return nil, fmt.Errorf("unsupported tls_version %q", c.TLSVersion)
		}
		tlsConn := tls.Client(conn, tlsConfig)
		_ = tlsConn.SetDeadline(time.Now().Add(timeout))
		if err = tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		_ = tlsConn.SetDeadline(time.Time{})
		conn = tlsConn
	}
	if usePayload {
		if strings.TrimSpace(c.Payload) == "" {
			conn.Close()
			return nil, errors.New("payload mode requires payload text")
		}
		ctx := payloadContext{host: c.SSHHost, port: c.SSHPort, proxyHost: c.ProxyHost, proxyPort: c.ProxyPort}
		if c.PayloadMode == "enhanced" {
			err = executeEnhancedPayload(conn, c.Payload, ctx)
		} else {
			var payload string
			payload, err = resolvePayload(c.Payload, ctx)
			if err == nil {
				_, err = io.WriteString(conn, payload)
			}
		}
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("payload: %w", err)
		}
	}
	return conn, nil
}

type payloadContext struct {
	host      string
	port      int
	proxyHost string
	proxyPort int
}

const userAgent = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.130 Safari/537.36"

func resolvePayload(input string, c payloadContext) (string, error) {
	var out strings.Builder
	for i := 0; i < len(input); {
		if input[i] == '\\' && i+1 < len(input) {
			switch input[i+1] {
			case 'r':
				out.WriteByte('\r')
				i += 2
				continue
			case 'n':
				out.WriteByte('\n')
				i += 2
				continue
			}
		}
		if input[i] == '[' {
			j := strings.IndexByte(input[i+1:], ']')
			if j >= 0 {
				j += i + 1
				raw := input[i+1 : j]
				token := strings.ToLower(strings.TrimSpace(raw))
				value, known := "", true
				switch token {
				case "cr":
					value = "\r"
				case "lf":
					value = "\n"
				case "crlf":
					value = "\r\n"
				case "lfcr":
					value = "\n\r"
				case "host", "ssh_host":
					value = c.host
				case "port", "ssh_port":
					value = strconv.Itoa(c.port)
				case "host_port", "ssh":
					value = fmt.Sprintf("%s:%d", c.host, c.port)
				case "proxy_host":
					if c.proxyHost != "" {
						value = c.proxyHost
					} else {
						known = false
					}
				case "proxy_port":
					if c.proxyPort > 0 {
						value = strconv.Itoa(c.proxyPort)
					} else {
						known = false
					}
				case "proxy":
					if c.proxyHost != "" && c.proxyPort > 0 {
						value = fmt.Sprintf("%s:%d", c.proxyHost, c.proxyPort)
					} else {
						known = false
					}
				case "ua":
					value = userAgent
				default:
					known = false
				}
				if known {
					out.WriteString(value)
				} else {
					out.WriteString(input[i : j+1])
				}
				i = j + 1
				continue
			}
		}
		out.WriteByte(input[i])
		i++
	}
	return out.String(), nil
}

func executeEnhancedPayload(conn net.Conn, input string, ctx payloadContext) error {
	// Mirrors PayloadTokenizer/PayloadParser: [split] writes immediately;
	// [delay]/[delay_split]/[split_delay] wait one second before next chunk.
	var chunk strings.Builder
	flush := func() error {
		if chunk.Len() == 0 {
			return nil
		}
		resolved, err := resolvePayload(chunk.String(), ctx)
		if err != nil {
			return err
		}
		if _, err = io.WriteString(conn, resolved); err != nil {
			return err
		}
		chunk.Reset()
		return nil
	}
	for i := 0; i < len(input); {
		if input[i] == '[' {
			j := strings.IndexByte(input[i+1:], ']')
			if j >= 0 {
				j += i + 1
				token := strings.ToLower(strings.TrimSpace(input[i+1 : j]))
				switch token {
				case "split", "splitnodelay", "instant_split":
					if err := flush(); err != nil {
						return err
					}
					i = j + 1
					continue
				case "delay", "delay_split", "split_delay":
					if err := flush(); err != nil {
						return err
					}
					time.Sleep(time.Second)
					i = j + 1
					continue
				}
				chunk.WriteString(input[i : j+1])
				i = j + 1
				continue
			}
		}
		chunk.WriteByte(input[i])
		i++
	}
	return flush()
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func sshConfig(c Config) (*ssh.ClientConfig, error) {
	auth := []ssh.AuthMethod{}
	if c.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(c.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("private_key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	} else if c.Password != "" {
		auth = append(auth, ssh.Password(c.Password))
	}
	if len(auth) == 0 {
		return nil, errors.New("set password or private_key")
	}
	cb, err := hostKeyCallback(c)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{User: c.Username, Auth: auth, HostKeyCallback: cb, Timeout: time.Duration(c.ConnectTimeoutSeconds) * time.Second}, nil
}

func handleSOCKS(conn net.Conn, client *ssh.Client, lg *log.Logger) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(conn)
	h := make([]byte, 2)
	if _, e := io.ReadFull(br, h); e != nil || h[0] != 5 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, e := io.ReadFull(br, methods); e != nil {
		return
	}
	noAuth := false
	for _, method := range methods {
		if method == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		_, _ = conn.Write([]byte{5, 255})
		return
	}
	if _, e := conn.Write([]byte{5, 0}); e != nil {
		return
	}
	head := make([]byte, 4)
	if _, e := io.ReadFull(br, head); e != nil {
		return
	}
	if head[0] != 5 {
		_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	if head[1] != 1 {
		_, _ = conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch head[3] {
	case 1:
		b := make([]byte, 4)
		if _, e := io.ReadFull(br, b); e != nil {
			return
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, e := io.ReadFull(br, b); e != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		n, e := br.ReadByte()
		if e != nil {
			return
		}
		b := make([]byte, int(n))
		if _, e = io.ReadFull(br, b); e != nil {
			return
		}
		host = string(b)
	default:
		_, _ = conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	p := make([]byte, 2)
	if _, e := io.ReadFull(br, p); e != nil {
		return
	}
	port := int(p[0])<<8 | int(p[1])
	if port == 0 {
		_, _ = conn.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	ch, reqs, err := client.OpenChannel("direct-tcpip", ssh.Marshal(struct {
		Dest    string
		Port    uint32
		Src     string
		SrcPort uint32
	}{host, uint32(port), "127.0.0.1", 0}))
	if err != nil {
		_, _ = conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		lg.Printf("channel %s: %v", target, err)
		return
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)
	_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	_ = conn.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(ch, br); _ = ch.CloseWrite(); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, ch); done <- struct{}{} }()
	<-done
}

func keepAlive(client *ssh.Client, seconds int, lg *log.Logger) {
	if seconds <= 0 {
		return
	}
	t := time.NewTicker(time.Duration(seconds) * time.Second)
	defer t.Stop()
	for range t.C {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		if err != nil {
			lg.Printf("SSH keepalive failed: %v", err)
			return
		}
	}
}

func runSession(ctx context.Context, c Config, lg *log.Logger) error {
	sc, err := sshConfig(c)
	if err != nil {
		return err
	}
	lg.Printf("connecting mode=%s endpoint=%s:%d", c.Mode, c.SSHHost, c.SSHPort)
	up, err := dialUpstream(c)
	if err != nil {
		return err
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(up, net.JoinHostPort(c.SSHHost, strconv.Itoa(c.SSHPort)), sc)
	if err != nil {
		up.Close()
		return fmt.Errorf("SSH handshake: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()
	lg.Printf("SSH authenticated; SOCKS5 listening on %s:%d", c.LocalSocksHost, c.LocalSocksPort)
	ln, err := net.Listen("tcp", net.JoinHostPort(c.LocalSocksHost, strconv.Itoa(c.LocalSocksPort)))
	if err != nil {
		return err
	}
	defer ln.Close()

	sshDone := make(chan error, 1)
	go func() { sshDone <- client.Wait() }()
	acceptDone := make(chan error, 1)
	go func() {
		for {
			conn, e := ln.Accept()
			if e != nil {
				acceptDone <- e
				return
			}
			go handleSOCKS(conn, client, lg)
		}
	}()
	keepCtx, cancelKeep := context.WithCancel(ctx)
	defer cancelKeep()
	go func() {
		if c.KeepAliveSeconds <= 0 {
			return
		}
		t := time.NewTicker(time.Duration(c.KeepAliveSeconds) * time.Second)
		defer t.Stop()
		for {
			select {
			case <-keepCtx.Done():
				return
			case <-t.C:
				_, _, e := client.SendRequest("keepalive@openssh.com", true, nil)
				if e != nil {
					lg.Printf("SSH keepalive failed: %v", e)
					_ = client.Close()
					return
				}
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil
	case e := <-sshDone:
		return fmt.Errorf("SSH connection lost: %w", e)
	case e := <-acceptDone:
		return fmt.Errorf("SOCKS listener stopped: %w", e)
	}
}

func run(path string) error {
	c, err := loadConfig(path)
	if err != nil {
		return err
	}
	if err = validateConfig(c); err != nil {
		return err
	}
	lg, closeLog := logger(c.LogFile)
	defer closeLog()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	attempt := 0
	for {
		err = runSession(ctx, c, lg)
		if ctx.Err() != nil {
			lg.Printf("shutdown requested")
			return nil
		}
		if err == nil {
			return nil
		}
		lg.Printf("session failed: %v", err)
		if !c.AutoReconnect {
			return err
		}
		attempt++
		if c.MaxReconnect > 0 && attempt > c.MaxReconnect {
			return fmt.Errorf("maximum reconnect attempts reached: %w", err)
		}
		wait := time.Second * time.Duration(1<<min(attempt-1, 6))
		if wait > 60*time.Second {
			wait = 60 * time.Second
		}
		lg.Printf("reconnecting in %s (attempt %d)", wait, attempt)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

var errHostKeyCaptured = errors.New("host key captured")

func scanHostKey(path string) error {
	c, err := loadConfig(path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(c.SSHHost) == "" || c.SSHPort < 1 || c.SSHPort > 65535 {
		return errors.New("valid ssh_host and ssh_port required")
	}
	conn, err := dialUpstream(c)
	if err != nil {
		return err
	}
	defer conn.Close()
	address := net.JoinHostPort(c.SSHHost, strconv.Itoa(c.SSHPort))
	cfg := &ssh.ClientConfig{User: "hostkey-scan", HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		entryHost := c.SSHHost
		if c.SSHPort != 22 {
			entryHost = "[" + c.SSHHost + "]:" + strconv.Itoa(c.SSHPort)
		}
		fmt.Printf("Fingerprint: %s\n", ssh.FingerprintSHA256(key))
		fmt.Printf("Known-hosts line:\n%s %s %s\n", entryHost, key.Type(), base64.StdEncoding.EncodeToString(key.Marshal()))
		return errHostKeyCaptured
	}, Timeout: time.Duration(c.ConnectTimeoutSeconds) * time.Second}
	_, _, _, err = ssh.NewClientConn(conn, address, cfg)
	if errors.Is(err, errHostKeyCaptured) {
		return nil
	}
	if err == nil {
		return errors.New("unexpected SSH host-key scan completion")
	}
	return fmt.Errorf("host-key scan: %w", err)
}

func validateConfig(c Config) error {
	if strings.TrimSpace(c.SSHHost) == "" {
		return errors.New("ssh_host is required")
	}
	if c.SSHPort < 1 || c.SSHPort > 65535 {
		return errors.New("ssh_port must be 1..65535")
	}
	if strings.TrimSpace(c.Username) == "" {
		return errors.New("username is required")
	}
	if c.Password == "" && c.PrivateKey == "" {
		return errors.New("password or private_key is required")
	}
	valid := map[string]bool{"ssh_only": true, "ssh_proxy": true, "ssh_sni": true, "ssh_proxy_payload": true, "ssh_payload_sni": true, "ssh_proxy_payload_sni": true}
	if !valid[c.Mode] {
		return fmt.Errorf("unsupported mode %q", c.Mode)
	}
	if strings.Contains(c.Mode, "proxy") && (c.ProxyHost == "" || c.ProxyPort < 1 || c.ProxyPort > 65535) {
		return errors.New("proxy mode requires proxy_host and valid proxy_port")
	}
	if strings.Contains(c.Mode, "sni") && strings.TrimSpace(c.TLSServerName) == "" {
		return errors.New("TLS/SNI mode requires tls_server_name")
	}
	if strings.Contains(c.Mode, "payload") && strings.TrimSpace(c.Payload) == "" {
		return errors.New("payload mode requires payload text")
	}
	if c.PayloadMode != "" && c.PayloadMode != "normal" && c.PayloadMode != "enhanced" {
		return errors.New("payload_mode must be normal or enhanced")
	}
	if c.HostKeyPolicy != "strict" && c.HostKeyPolicy != "insecure" {
		return errors.New("host_key_policy must be strict or insecure")
	}
	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: sshprotocol <run|check|scan-host-key> <config.json>")
		os.Exit(2)
	}
	if os.Args[1] == "scan-host-key" {
		if e := scanHostKey(os.Args[2]); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if os.Args[1] == "check" {
		c, e := loadConfig(os.Args[2])
		if e == nil {
			e = validateConfig(c)
		}
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		fmt.Println("config OK")
		return
	}
	if os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
	if err := run(os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
