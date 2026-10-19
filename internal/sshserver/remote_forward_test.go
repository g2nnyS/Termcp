package sshserver

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/open-mcp-ai/termcp/internal/forward"
)

// TestRemoteForwardOnInternalEndpoint locks the wiring that makes `ssh -R` work
// against the built-in in-memory sshd.
//
// It exists because two separate omissions made the feature fail in a way that
// reads as somebody else's policy: charmbracelet/ssh ships
// ForwardedTCPHandler but puts nothing in DefaultRequestHandlers, and its
// ReversePortForwardingCallback denies everything when nil. With neither in
// place the client gets "tcpip-forward request denied by peer", which the docs
// used to explain as the target's GatewayPorts setting — the feature was never
// wired, and nothing said so.
//
// The shape matters: the assertion is that traffic entering the port the TARGET
// opened comes back out of the service, which only holds if the library's
// forwarded-tcpip channel is really being used.
func TestRemoteForwardOnInternalEndpoint(t *testing.T) {
	s := New()
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	// The service this forward exists to publish.
	svc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	go func() {
		for {
			c, err := svc.Accept()
			if err != nil {
				return
			}
			io.WriteString(c, "svc-answer")
			c.Close()
		}
	}()
	svcPort := svc.Addr().(*net.TCPAddr).Port

	cli := dialServer(t, s, mintCfg(t, s))
	defer cli.Close()

	// The port the target will bind is chosen here because 0 is rejected for -R
	// (it is the number the TARGET binds, so the caller has to pick it).
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rPort := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	fm := forward.NewForwardManager()
	fw, err := fm.CreateRemote("sid", "internal", "127.0.0.1", rPort, "127.0.0.1", svcPort, cli)
	if err != nil {
		t.Fatalf("remote forward on the internal endpoint: %v", err)
	}
	defer fm.Close(fw.ForwardID)

	// The reported address must be the one the listener holds, not the request:
	// for port 0 the request names nothing dialable.
	if fw.ListenAddr != net.JoinHostPort("127.0.0.1", strconv.Itoa(rPort)) {
		t.Errorf("ListenAddr = %q, want %s", fw.ListenAddr, net.JoinHostPort("127.0.0.1", strconv.Itoa(rPort)))
	}

	nc, err := net.DialTimeout("tcp", fw.ListenAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial the -R port %q: %v", fw.ListenAddr, err)
	}
	defer nc.Close()
	nc.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	n, err := nc.Read(buf)
	if err != nil {
		t.Fatalf("read through the -R tunnel: %v", err)
	}
	if string(buf[:n]) != "svc-answer" {
		t.Fatalf("got %q through the tunnel, want %q", buf[:n], "svc-answer")
	}
}

// TestRemoteForwardRefusesNonLoopback pins the other half of the wiring: the
// bind address arrives in the client's request, so it is checked rather than
// trusted. An in-memory peer is a session on this host and has no business
// asking the server to listen for the network.
func TestRemoteForwardRefusesNonLoopback(t *testing.T) {
	s := New()
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	cli := dialServer(t, s, mintCfg(t, s))
	defer cli.Close()

	for _, host := range []string{"0.0.0.0", "::"} {
		ln, err := cli.Listen("tcp", net.JoinHostPort(host, "0"))
		if err == nil {
			ln.Close()
			t.Fatalf("the server allowed a %s reverse-forward bind", host)
		}
		if _, ok := err.(*ssh.OpenChannelError); ok {
			t.Errorf("bind %s failed with %v; want a refusal of the tcpip-forward request", host, err)
		}
	}
}

// TestRemoteForwardLoopbackAllowed is the counterpart to the refusal: the guard
// must not have blocked the sane case (the test above would still pass if the
// handler were missing entirely).
func TestRemoteForwardLoopbackAllowed(t *testing.T) {
	s := New()
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	cli := dialServer(t, s, mintCfg(t, s))
	defer cli.Close()

	ln, err := cli.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("loopback reverse forward refused: %v", err)
	}
	defer ln.Close()
	if got := ln.Addr().String(); got == "" || got == "127.0.0.1:0" {
		t.Errorf("listener reports %q, want the allocated address", got)
	}
}
