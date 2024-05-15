package network

import (
	"net"
)

type CIDR net.IPNet

func (c *CIDR) UnmarshalText(text []byte) error {
	// empty strings are allowed
	if string(text) == "" {
		return nil
	}
	_, net, err := net.ParseCIDR(string(text))
	if err != nil {
		return err
	}
	*c = CIDR(*net)
	return nil
}

func (c CIDR) String() string {
	s := c.ToIPNet().String()
	if s == "<nil>" {
		return ""
	}
	return s
}

func (c CIDR) ToIPNet() *net.IPNet {
	netw := net.IPNet(c)
	return &netw
}
