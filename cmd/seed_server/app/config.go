package app

import (
	"bytes"
	"net"
	"net/netip"
	"text/template"
)

var openvpnConfigTemplate = `
mode server
tls-server
topology subnet

# Additonal optimizations
txqueuelen 1000

data-ciphers AES-256-GCM:AES-256-CBC

# port can always be 1194 here as it is not visible externally. A different
# port can be configured for the external load balancer in the service
# manifest
port 1194

keepalive 10 60

# client-config-dir to push client specific configuration
client-config-dir /client-config-dir

key "/srv/secrets/vpn-server/tls.key"
cert "/srv/secrets/vpn-server/tls.crt"
ca "/srv/secrets/vpn-server/ca.crt"
dh none

auth SHA256
tls-auth "/srv/secrets/tlsauth/vpn.tlsauth" 0

{{- if (eq .Env.IPFamilies "IPv4") }}
proto tcp4-server
server {{ netIP .OpenVPNNetwork }} {{ cidrMask .OpenVPNNetwork }} nopool
ifconfig-pool {{ .IPv4PoolStartIP }} {{ .IPv4PoolEndIP }}

{{- range .ShootNetworks }}
route {{ netIP . }} {{ cidrMask . }}
{{- end }}
{{- end }}

{{- if (eq .Env.IPFamilies "IPv6") }}
proto tcp6-server
server-ipv6 {{ net .OpenVPNNetwork }}

{{- range .ShootNetworks }}
route-ipv6 {{ net . }}
{{- end }}
{{- end }}

{{- if .IsHA }}

client-to-client
duplicate-cn
{{- end }}

dev {{ .Device }}

{{/* Add firewall rules to block all traffic originating from the shoot cluster.
     The scripts are run after the tun device has been created (up) or removed (down). */ -}}
script-security 2
up "/bin/seed-server firewall --mode up --device {{ .Device }}"
down "/bin/seed-server firewall --mode down --device {{ .Device }}"

{{ if not (eq .Env.StatusPath "") -}}
status {{ .Env.StatusPath }} 15
status-version 2
{{- end -}}
`

var vpnShootClientTemplate = `
{{- if (eq .Env.IPFamilies  "IPv4") }}
{{- range .ShootNetworks }}
iroute {{ netIP . }} {{ cidrMask . }}
{{- end }}
{{- end }}

{{- if (eq .Env.IPFamilies "IPv6") }}
{{- range .ShootNetworks }}
iroute-ipv6 {{ net . }}
{{- end }}
{{- end }}
`

var vpnShootClientHATemplate = `
ifconfig-push {{ .StartIP }} {{ cidrMask .OpenVPNNetwork }}
`

type config struct {
	Device          string
	IPv4PoolStartIP string
	IPv4PoolEndIP   string
	OpenVPNNetwork  netip.Prefix
	IsHA            bool
	ShootNetworks   []netip.Prefix
	Env             Environment
}

var funcs = map[string]any{"net": netFunc, "netIP": netIP, "cidrMask": cidrMask}

func GenerateOpenVPNConfig(cfg config) (string, error) {
	t, err := template.New("openvpn.cfg").
		Funcs(funcs).
		Parse(openvpnConfigTemplate)
	if err != nil {
		return "", err
	}
	buf := &bytes.Buffer{}
	if err := t.Execute(buf, &cfg); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func GenerateVPNShootClient(cfg config) (string, error) {
	t, err := template.New("vpn-shoot-client").
		Funcs(funcs).
		Parse(vpnShootClientTemplate)
	if err != nil {
		return "", err
	}
	buf := &bytes.Buffer{}
	if err := t.Execute(buf, &cfg); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func GenerateVPNShootClientHA(cfg config, startIP string) (string, error) {
	t, err := template.New("vpn-shoot-client-ha").
		Funcs(funcs).
		Parse(vpnShootClientHATemplate)
	if err != nil {
		return "", err
	}
	buf := &bytes.Buffer{}
	if err := t.Execute(buf, map[string]any{"OpenVPNNetwork": cfg.OpenVPNNetwork, "StartIP": startIP}); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func netFunc(n netip.Prefix) string {
	return n.String()
}

func netIP(n netip.Prefix) string {
	return n.Addr().String()
}

func cidrMask(n netip.Prefix) string {
	mask := net.CIDRMask(n.Bits(), 32)
	return net.IPv4(255, 255, 255, 255).Mask(mask).String()
}
