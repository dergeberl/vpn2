package config

import (
	"strconv"
	"strings"

	"github.com/caarlos0/env/v10"
	"github.com/go-logr/logr"
)

type Config struct {
	TCP struct {
		KeepAliveTime     int64 `env:"KEEPALIVE_TIME" envDefault:"7200"`
		KeepAliveInterval int64 `env:"KEEPALIVE_INTVL" envDefault:"75"`
		KeepAliveProbes   int64 `env:"KEEPALIVE_PROBES" envDefault:"9"`
	} `envPrefix:"TCP_"`
	IPFamilies                   string `env:"IP_FAMILIES" envDefault:"IPv4"`
	Endpoint                     string `env:"ENDPOINT"`
	OpenVPNPort                  int    `env:"OPENVPN_PORT" envDefault:"8132"`
	VPNNetwork                   string `env:"VPN_NETWORK"`
	IsShootClient                bool   `env:"IS_SHOOT_CLIENT"`
	PodName                      string `env:"POD_NAME"`
	Namespace                    string `env:"NAMESPACE"`
	VPNServerIndex               string `env:"VPN_SERVER_INDEX"`
	ExitAfterKernelSettings      bool   `env:"EXIT_AFTER_CONFIGURING_KERNEL_SETTINGS"`
	VPNClientIndex               int
	ConfigureBonding             bool   `env:"CONFIGURE_BONDING"`
	ReversedVPNHeader            string `env:"REVERSED_VPN_HEADER" envDefault:"invalid-host"`
	HAVPNClients                 int    `env:"HA_VPN_CLIENTS"`
	HAVPNServers                 int    `env:"HA_VPN_SERVERS"`
	StartIndex                   int    `env:"START_INDEX" envDefault:"200"`
	EndIndex                     int    `env:"END_INDEX" envDefault:"254"`
	PodLabelSelector             string `env:"POD_LABEL_SELECTOR" envDefault:"app=kubernetes,role=apiserver"`
	WaitSeconds                  int    `env:"WAIT_SECONDS" envDefault:"2"`
	DoNotConfigureKernelSettings bool   `env:"DO_NOT_CONFIGURE_KERNEL_SETTINGS" envDefault:"false"`
}

func GetConfig(log logr.Logger) (Config, error) {
	cfg := Config{}
	if err := env.Parse(&cfg); err != nil {
		return cfg, err
	}
	if cfg.VPNServerIndex != "" {
		if cfg.VPNNetwork == "" {
			if cfg.IPFamilies == "IPv4" {
				cfg.VPNNetwork = "192.168.123.0/24"
			} else {
				cfg.VPNNetwork = "fd8f:6d53:b97a:1::/120"
			}
		}
	} else {
		// Always use ipv6 ULA for the vpn transfer network if not HA
		cfg.VPNNetwork = "fd8f:6d53:b97a:1::/120"
	}
	cfg.VPNClientIndex = -1
	if cfg.PodName != "" {
		podNameSlice := strings.Split(cfg.PodName, "-")
		clientIndex, err := strconv.Atoi(podNameSlice[len(podNameSlice)-1])
		if err == nil {
			cfg.VPNClientIndex = clientIndex
		}
	}
	log.Info("config parsed", "config", cfg)
	return cfg, nil
}
