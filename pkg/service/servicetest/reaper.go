//go:build integration

package servicetest

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
)

// reaperPort is the port Ryuk listens on inside its container.
const reaperPort = "8080/tcp"

// held is this binary's own connection to the session's Ryuk. Closed by the exit.
var held struct {
	mu   sync.Mutex
	conn net.Conn
}

// holdReaper keeps one connection Ryuk has acknowledged open for the life of the
// test binary. The library's first connection can land on docker-proxy before
// Ryuk listens and fail unseen. Ryuk then reaps the shared container mid-run the
// first time no other client is connected.
// in: context, a container of this session. out: error.
func holdReaper(ctx context.Context, ctr testcontainers.Container) error {
	held.mu.Lock()
	defer held.mu.Unlock()
	if held.conn != nil || testcontainers.ReadConfig().Config.RyukDisabled {
		return nil
	}
	conn, err := dialReaper(ctx, ctr)
	if err != nil {
		return err
	}
	held.conn = conn
	return nil
}

// dialReaper connects to the session's Ryuk and waits for its ACK on the session filter.
// in: context, a container of this session (for the daemon host). out: open connection, error.
func dialReaper(ctx context.Context, ctr testcontainers.Container) (net.Conn, error) {
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	defer func() { _ = cli.Close() }()
	res, err := cli.ContainerInspect(ctx, "reaper_"+testcontainers.SessionID(), client.ContainerInspectOptions{})
	if err != nil {
		return nil, fmt.Errorf("inspect reaper: %w", err)
	}
	bindings := res.Container.NetworkSettings.Ports[network.MustParsePort(reaperPort)]
	if len(bindings) == 0 {
		return nil, fmt.Errorf("reaper port %s has no host binding", reaperPort)
	}
	host, err := ctr.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("daemon host: %w", err)
	}
	addr := net.JoinHostPort(host, bindings[0].HostPort)

	filters := make([]string, 0, 5)
	for k, v := range testcontainers.GenericLabels() {
		filters = append(filters, "label="+k+"="+v)
	}
	slices.Sort(filters)
	filter := strings.Join(filters, "&") + "\n"

	deadline := time.Now().Add(startupBudget)
	for {
		conn, err := handshake(addr, filter)
		if err == nil {
			return conn, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("reaper handshake %s: %w", addr, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// handshake sends filter to Ryuk at addr and reads its ACK.
// in: address, filter line. out: the acknowledged connection, error.
func handshake(addr, filter string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.Write([]byte(filter)); err == nil {
		var line string
		if line, err = bufio.NewReader(conn).ReadString('\n'); err == nil && line != "ACK\n" {
			err = fmt.Errorf("unexpected reply %q", line)
		}
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
