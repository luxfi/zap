// Package zapmdns publishes and browses _hanzo._tcp.local. services per
// HIP-0069. Single source of truth for the service-type, TXT key list and
// role enum across every Go service in the Hanzo stack (kms, mpc, base,
// ingress, gateway, static).
package zapmdns

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/mdns"
)

// ServiceType is the canonical mDNS service-type for the Hanzo mesh.
const ServiceType = "_hanzo._tcp"

// Roles defined by HIP-0069.
const (
	RoleMCP     = "mcp"
	RoleIAM     = "iam"
	RoleKMS     = "kms"
	RoleMPC     = "mpc"
	RoleBase    = "base"
	RoleEngine  = "engine"
	RoleBrowser = "browser"
	RoleNode    = "node"
	RoleDesktop = "desktop"
	RoleGateway = "gateway"
	RoleStatic  = "static"
)

// Service is one peer found on the LAN.
type Service struct {
	Role         string
	ServerID     string
	Org          string
	Version      string
	Proto        string // zap/1, http/1.1, grpc/1
	Capabilities []string
	AgentLabel   string
	Auth         string
	Host         string
	Port         int
}

// URL returns a transport-appropriate URL for the service.
func (s Service) URL() string {
	scheme := "ws"
	if strings.HasPrefix(s.Proto, "http") {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%d/", scheme, s.Host, s.Port)
}

// PublishOptions captures the TXT keys defined by HIP-0069.
type PublishOptions struct {
	Role         string   // required (one of Role* constants)
	Port         int      // required
	ServerID     string   // required (defaults to <role>-<host>-<pid>)
	Org          string   // default "hanzo"
	Version      string   // required
	Proto        string   // default "zap/1"
	Capabilities []string // free-form
	AgentLabel   string
	Auth         string // none | iam | mtls (default "none")
	Host         string // optional bind override
}

// Publisher retracts the announcement on Close.
type Publisher struct {
	server *mdns.Server
}

// Close retracts the mDNS announcement.
func (p *Publisher) Close() error {
	if p == nil || p.server == nil {
		return nil
	}
	return p.server.Shutdown()
}

// Publish advertises a service on the LAN. Returns a *Publisher whose Close
// retracts the record. Returns an error if `Role`, `Port`, or `Version`
// are missing.
func Publish(opts PublishOptions) (*Publisher, error) {
	if opts.Role == "" {
		return nil, fmt.Errorf("zapmdns: Role is required")
	}
	if opts.Port == 0 {
		return nil, fmt.Errorf("zapmdns: Port is required")
	}
	if opts.Version == "" {
		return nil, fmt.Errorf("zapmdns: Version is required")
	}
	host, _ := os.Hostname()
	if opts.ServerID == "" {
		opts.ServerID = fmt.Sprintf("%s-%s-%d", opts.Role, host, os.Getpid())
	}
	if opts.Org == "" {
		opts.Org = "hanzo"
	}
	if opts.Proto == "" {
		opts.Proto = "zap/1"
	}
	if opts.Auth == "" {
		opts.Auth = "none"
	}

	txt := []string{
		"role=" + opts.Role,
		"server_id=" + opts.ServerID,
		"org=" + opts.Org,
		"version=" + opts.Version,
		"proto=" + opts.Proto,
		"capabilities=" + strings.Join(opts.Capabilities, ","),
		"auth=" + opts.Auth,
	}
	if opts.AgentLabel != "" {
		txt = append(txt, "agent_label="+opts.AgentLabel)
	}

	info, err := mdns.NewMDNSService(
		opts.ServerID,                // instance name
		ServiceType+".local.",        // service type
		"",                           // domain (default)
		host+".local.",               // host
		opts.Port,
		nil,                          // ips (auto-detect)
		txt,
	)
	if err != nil {
		return nil, fmt.Errorf("zapmdns: build ServiceInfo: %w", err)
	}
	srv, err := mdns.NewServer(&mdns.Config{Zone: info})
	if err != nil {
		return nil, fmt.Errorf("zapmdns: start mdns server: %w", err)
	}
	return &Publisher{server: srv}, nil
}

// Browse lists every Hanzo-domain service on the LAN within the given
// timeout. Empty role filter returns all roles.
func Browse(ctx context.Context, role string, timeout time.Duration) ([]Service, error) {
	entries := make(chan *mdns.ServiceEntry, 32)
	defer close(entries)

	out := make([]Service, 0, 16)
	done := make(chan struct{})
	go func() {
		for e := range entries {
			s := parseEntry(e)
			if s == nil {
				continue
			}
			if role != "" && s.Role != role {
				continue
			}
			out = append(out, *s)
		}
		close(done)
	}()

	params := &mdns.QueryParam{
		Service: ServiceType,
		Domain:  "local",
		Timeout: timeout,
		Entries: entries,
	}
	if err := mdns.Query(params); err != nil {
		return nil, fmt.Errorf("zapmdns: query: %w", err)
	}
	<-done
	return out, nil
}

func parseEntry(e *mdns.ServiceEntry) *Service {
	if e == nil {
		return nil
	}
	s := &Service{Port: e.Port}
	if e.AddrV4 != nil {
		s.Host = e.AddrV4.String()
	} else if e.AddrV6 != nil {
		s.Host = e.AddrV6.String()
	} else if ip := net.ParseIP(e.Host); ip != nil {
		s.Host = ip.String()
	} else {
		s.Host = strings.TrimSuffix(e.Host, ".")
	}
	for _, kv := range e.InfoFields {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "role":
			s.Role = v
		case "server_id":
			s.ServerID = v
		case "org":
			s.Org = v
		case "version":
			s.Version = v
		case "proto":
			s.Proto = v
		case "capabilities":
			if v != "" {
				s.Capabilities = strings.Split(v, ",")
			}
		case "agent_label":
			s.AgentLabel = v
		case "auth":
			s.Auth = v
		}
	}
	if s.Role == "" {
		return nil // not a Hanzo-spec service
	}
	if s.Org == "" {
		s.Org = "hanzo"
	}
	return s
}
