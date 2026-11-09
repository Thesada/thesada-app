package mailer

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// TestSanitizeHeader verifies CR/LF are stripped so a hostile recipient or
// subject cannot inject additional headers or a message body.
func TestSanitizeHeader(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "user@example.com", "user@example.com"},
		{"subject", "Your device alert", "Your device alert"},
		{"crlf header inject", "user@example.com\r\nBcc: victim@example.com", "user@example.comBcc: victim@example.com"},
		{"lf only", "Subject line\ninjected", "Subject lineinjected"},
		{"cr only", "a\rb", "ab"},
		{"body inject", "subj\r\n\r\nfake body", "subjfake body"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeHeader(c.in); got != c.want {
				t.Errorf("sanitizeHeader(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// listen starts a TCP server on loopback that runs serve per connection.
func listen(t *testing.T, serve func(net.Conn)) (host, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
	host, port, _ = net.SplitHostPort(ln.Addr().String())
	return host, port
}

// A server that accepts and never greets fails the send inside the timeout.
func TestSend_StalledServerTimesOut(t *testing.T) {
	host, port := listen(t, func(c net.Conn) {
		time.Sleep(10 * time.Second)
		_ = c.Close()
	})
	m := &Mailer{host: host, port: port, from: "app@example.com", timeout: 200 * time.Millisecond}
	done := make(chan error, 1)
	go func() { done <- m.Send("u@example.com", "s", "b") }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("send to a stalled server succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("send to a stalled server hung past its timeout")
	}
}

// A minimal SMTP server gets the whole message through the bounded client.
func TestSendMIME_DeliversThroughSession(t *testing.T) {
	got := make(chan string, 1)
	host, port := listen(t, func(c net.Conn) {
		defer func() { _ = c.Close() }()
		r := bufio.NewReader(c)
		say := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
		say("220 test")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					got <- data.String()
					say("250 ok")
					continue
				}
				data.WriteString(line)
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"):
				say("250-test")
				say("250 AUTH PLAIN")
			case strings.HasPrefix(cmd, "AUTH"):
				say("235 ok")
			case cmd == "DATA":
				inData = true
				say("354 go")
			case cmd == "QUIT":
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	})
	m := &Mailer{host: host, port: port, user: "u", pass: "p", from: "app@example.com", timeout: 2 * time.Second}
	if err := m.SendMIME("u@example.com", "subj", "text body", "<p>html</p>"); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case msg := <-got:
		if !strings.Contains(msg, "Subject: subj") || !strings.Contains(msg, "<p>html</p>") {
			t.Fatalf("message lost parts: %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never received DATA")
	}
}
