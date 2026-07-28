// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Network returns the net package's network name for addr: a filesystem
// path names a unix socket, anything else is a host:port TCP address.
//
// It is the ONE rule the listener and the dialer both use, so a node can
// never bind one transport and be dialled on another. An address is a
// path when it is absolute, explicitly relative, or in Linux's abstract
// namespace ("@name") — none of which is a legal host:port.
func Network(addr string) string {
	switch {
	case strings.HasPrefix(addr, "/"),
		strings.HasPrefix(addr, "./"),
		strings.HasPrefix(addr, "../"),
		strings.HasPrefix(addr, "@"):
		return "unix"
	default:
		return "tcp"
	}
}

// removeDeadSocket clears a socket file left behind by a process that did
// not unlink it, which would otherwise make bind fail with EADDRINUSE
// while nothing is listening. A socket someone IS listening on is left
// alone, so two live nodes cannot silently steal each other's address.
func removeDeadSocket(path string) error {
	if strings.HasPrefix(path, "@") {
		return nil // abstract sockets have no filesystem entry
	}
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket", path)
	}
	if c, err := net.DialTimeout("unix", path, 200*time.Millisecond); err == nil {
		c.Close()
		return fmt.Errorf("%s is already served by a live node", path)
	}
	return os.Remove(path)
}
