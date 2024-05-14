package app

import (
	"bytes"
	"net"
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

{{- if (eq .IPFamilies "IPv4") }}
proto tcp4-server
server {{ netIP .OpenVPNNetwork }} {{ cidrMask .OpenVPNNetwork }} nopool
ifconfig-pool {{ .IPv4PoolStartIP }} {{ .IPv4PoolEndIP }}

route {{ netIP .ServiceNetwork }} {{ cidrMask .ServiceNetwork }}
route {{ netIP .PodNetwork }} {{ cidrMask .PodNetwork }}
{{- range .NodeNetworks }}
route {{ netIP . }} {{ cidrMask . }}
{{- end }}
{{- end }}

{{- if (eq .IPFamilies "IPv6") }}
proto tcp6-server
server-ipv6 {{ net .OpenVPNNetwork }}

route-ipv6 {{ net .ServiceNetwork }}
route-ipv6 {{ net .PodNetwork }}
{{- range .NodeNetworks }}
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
up "/firewall.sh on {{ .Device }}"
down "/firewall.sh off {{ .Device }}"

{{ if not (eq .StatusPath "") -}}
status {{ .StatusPath }} 15
status-version 2
{{- end -}}
`

var vpnShootClientTemplate = `
{{- if (eq .IPFamilies  "IPv4") }}
iroute {{ netIP .ServiceNetwork }} {{ cidrMask .ServiceNetwork }}
iroute {{ netIP .PodNetwork }} {{ cidrMask .PodNetwork }}
{{- range .NodeNetworks }}
iroute {{ netIP . }} {{ cidrMask . }}
{{- end }}
{{- end }}

{{- if (eq .IPFamilies "IPv6") }}
iroute-ipv6 {{ net .ServiceNetwork }}
iroute-ipv6 {{ net .PodNetwork }}
{{- range .NodeNetworks }}
route-ipv6 {{ net . }}
{{- end }}
{{- end }}
`

var vpnShootClientHATemplate = `
ifconfig-push {{ .StartIP }} {{ cidrMask .OpenVPNNetwork }}
`

type config struct {
	Device          string
	IPFamilies      string
	IPv4PoolStartIP string
	IPv4PoolEndIP   string
	OpenVPNNetwork  net.IPNet
	IsHA            bool
	StatusPath      string
	ServiceNetwork  net.IPNet
	PodNetwork      net.IPNet
	NodeNetworks    []net.IPNet
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

func netFunc(n net.IPNet) string {
	return n.String()
}

func netIP(n net.IPNet) string {
	return n.IP.String()
}

func cidrMask(ipnet net.IPNet) string {
	mask := net.CIDRMask(ipnet.Mask.Size())
	return net.IPv4(255, 255, 255, 255).Mask(mask).String()
}
