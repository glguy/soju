package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"git.sr.ht/~emersion/go-scfg"
)

var (
	DefaultPath          string
	DefaultUnixAdminPath = "/run/soju/admin"
)

type IPSet []*net.IPNet

func (set IPSet) Contains(ip net.IP) bool {
	for _, n := range set {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// loopbackIPs contains the loopback networks 127.0.0.0/8 and ::1/128.
var loopbackIPs = IPSet{
	&net.IPNet{
		IP:   net.IP{127, 0, 0, 0},
		Mask: net.CIDRMask(8, 32),
	},
	&net.IPNet{
		IP:   net.IPv6loopback,
		Mask: net.CIDRMask(128, 128),
	},
}

func parseDuration(s string) (time.Duration, error) {
	if !strings.HasSuffix(s, "d") {
		return 0, fmt.Errorf("missing 'd' suffix in duration")
	}
	s = strings.TrimSuffix(s, "d")
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration: %v", err)
	}
	return time.Duration(v * 24 * float64(time.Hour)), nil
}

type TLS struct {
	CertPath, KeyPath string
}

type DB struct {
	Driver, Source string
}

type MsgStore struct {
	Driver, Source string
}

type Auth struct {
	Driver, Source string
}

type Server struct {
	Listen   []string
	TLS      *TLS
	Hostname string
	Title    string
	MOTDPath string

	DB       DB
	MsgStore MsgStore
	Auth     Auth

	HTTPOrigins    []string
	AcceptProxyIPs IPSet

	MaxUserNetworks           int
	UpstreamUserIPs           []*net.IPNet
	DisableInactiveUsersDelay time.Duration
	EnableUsersOnAuth         bool
}

func Defaults() *Server {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	return &Server{
		Hostname: hostname,
		DB: DB{
			Driver: "sqlite3",
			Source: "soju.db",
		},
		MsgStore: MsgStore{
			Driver: "memory",
		},
		Auth: Auth{
			Driver: "internal",
		},
		MaxUserNetworks: -1,
	}
}

func Load(path string) (*Server, error) {
	var raw struct {
		Listen              []string   `scfg:"listen"`
		Hostname            string     `scfg:"hostname"`
		Title               string     `scfg:"title"`
		MOTD                string     `scfg:"motd"`
		TLS                 *[2]string `scfg:"tls"`
		DB                  *[2]string `scfg:"db"`
		MessageStore        *rawDriver `scfg:"message-store"`
		Log                 *rawDriver `scfg:"log"`
		Auth                *rawDriver `scfg:"auth"`
		HTTPOrigin          []string   `scfg:"http-origin"`
		AcceptProxyIP       []string   `scfg:"accept-proxy-ip"`
		MaxUserNetworks     int        `scfg:"max-user-networks"`
		UpstreamUserIP      []string   `scfg:"upstream-user-ip"`
		DisableInactiveUser string     `scfg:"disable-inactive-user"`
		EnableUserOnAuth    string     `scfg:"enable-user-on-auth"`
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := scfg.NewDecoder(f).Decode(&raw); err != nil {
		return nil, err
	}

	srv := Defaults()

	srv.Listen = raw.Listen
	if raw.Hostname != "" {
		srv.Hostname = raw.Hostname
	}
	srv.Title = raw.Title
	srv.MOTDPath = raw.MOTD
	if raw.TLS != nil {
		srv.TLS = &TLS{CertPath: raw.TLS[0], KeyPath: raw.TLS[1]}
	}
	if raw.DB != nil {
		srv.DB = DB{Driver: raw.DB[0], Source: raw.DB[1]}
	}
	if raw.MessageStore == nil {
		raw.MessageStore = raw.Log
	}
	if raw.MessageStore != nil {
		switch raw.MessageStore.Driver {
		case "memory", "db":
			// nothing to do
		case "fs":
			if raw.MessageStore.Source == "" {
				return nil, fmt.Errorf("directive message-store: driver %q requires a source", raw.MessageStore.Driver)
			}
		default:
			return nil, fmt.Errorf("directive message-store: unknown driver %q", raw.MessageStore.Driver)
		}
		srv.MsgStore = MsgStore{raw.MessageStore.Driver, raw.MessageStore.Source}
	}
	if raw.Auth != nil {
		switch raw.Auth.Driver {
		case "internal", "pam":
			// nothing to do
		case "oauth2":
			if raw.MessageStore.Source == "" {
				return nil, fmt.Errorf("directive auth: driver %q requires a source", raw.Auth.Driver)
			}
		default:
			return nil, fmt.Errorf("directive auth: unknown driver %q", raw.Auth.Driver)
		}
		srv.Auth = Auth{raw.Auth.Driver, raw.Auth.Source}
	}
	srv.HTTPOrigins = raw.HTTPOrigin
	for _, s := range raw.AcceptProxyIP {
		if s == "localhost" {
			srv.AcceptProxyIPs = append(srv.AcceptProxyIPs, loopbackIPs...)
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("directive accept-proxy-ip: failed to parse CIDR: %v", err)
		}
		srv.AcceptProxyIPs = append(srv.AcceptProxyIPs, n)
	}
	srv.MaxUserNetworks = raw.MaxUserNetworks
	var hasIPv4, hasIPv6 bool
	for _, s := range raw.UpstreamUserIP {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("directive upstream-user-ip: failed to parse CIDR: %v", err)
		}
		if n.IP.To4() == nil {
			if hasIPv6 {
				return nil, fmt.Errorf("directive upstream-user-ip: found two IPv6 CIDRs")
			}
			hasIPv6 = true
		} else {
			if hasIPv4 {
				return nil, fmt.Errorf("directive upstream-user-ip: found two IPv4 CIDRs")
			}
			hasIPv4 = true
		}
		srv.UpstreamUserIPs = append(srv.UpstreamUserIPs, n)
	}
	if raw.DisableInactiveUser != "" {
		dur, err := parseDuration(raw.DisableInactiveUser)
		if err != nil {
			return nil, fmt.Errorf("directive disable-inactive-user: %v", err)
		} else if dur < 0 {
			return nil, fmt.Errorf("directive disable-inactive-user: duration must be positive")
		}
		srv.DisableInactiveUsersDelay = dur
	}
	if raw.EnableUserOnAuth != "" {
		b, err := strconv.ParseBool(raw.EnableUserOnAuth)
		if err != nil {
			return nil, fmt.Errorf("directive enable-user-on-auth: %v", err)
		}
		srv.EnableUsersOnAuth = b
	}

	return srv, nil
}

type rawDriver struct {
	Driver string
	Source string
}

var _ scfg.DirectiveUnmarshaler = (*rawDriver)(nil)

func (driver *rawDriver) UnmarshalScfgDirective(dir *scfg.Directive) error {
	if len(dir.Children) > 0 {
		return fmt.Errorf("directive %v doesn't accept children", dir.Name)
	}
	switch len(dir.Params) {
	case 2:
		driver.Source = dir.Params[1]
		fallthrough
	case 1:
		driver.Driver = dir.Params[0]
	default:
		return fmt.Errorf("directive %v requires exactly 1 or 2 parameters", dir.Name)
	}
	return nil
}
