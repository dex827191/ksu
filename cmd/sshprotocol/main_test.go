package main

import (
	"io"
	"net"
	"strings"
	"testing"
)

func TestResolvePayloadPlaceholders(t *testing.T) {
	ctx := payloadContext{host: "ssh.example", port: 443, proxyHost: "proxy.example", proxyPort: 8080}
	got, err := resolvePayload("[host]|[port]|[host_port]|[proxy]|[crlf]\\n[ua]", ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ssh.example", "443", "ssh.example:443", "proxy.example:8080", "\r\n\n", userAgent} {
		if !strings.Contains(got, want) {
			t.Fatalf("resolved payload missing %q: %q", want, got)
		}
	}
}

func TestEnhancedPayloadSplitTokens(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	done := make(chan string, 1)
	go func() { b, _ := io.ReadAll(server); done <- string(b) }()
	err := executeEnhancedPayload(client, "A[split]B[splitnodelay]C[instant_split]D", payloadContext{host: "h", port: 22})
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if got := <-done; got != "ABCD" {
		t.Fatalf("got %q", got)
	}
}

func TestValidateSixSupportedModes(t *testing.T) {
	base := Config{SSHHost: "host", SSHPort: 22, Username: "u", Password: "p", HostKeyPolicy: "strict"}
	modes := []string{"ssh_only", "ssh_proxy", "ssh_sni", "ssh_proxy_payload", "ssh_payload_sni", "ssh_proxy_payload_sni"}
	for _, mode := range modes {
		c := base
		c.Mode = mode
		if strings.Contains(mode, "proxy") {
			c.ProxyHost = "proxy"
			c.ProxyPort = 8080
		}
		if strings.Contains(mode, "sni") {
			c.TLSServerName = "sni.example"
		}
		if strings.Contains(mode, "payload") {
			c.Payload = "CONNECT [host]:[port][crlf][crlf]"
		}
		if err := validateConfig(c); err != nil {
			t.Errorf("%s: %v", mode, err)
		}
	}
}
