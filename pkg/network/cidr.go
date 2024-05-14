package network

import (
	"fmt"
	"net"
)

func ValidateCIDR(networkCIDR string, ipFamily string) (*net.IPNet, error) {
	_, cidr, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		return nil, err
	}
	length, _ := cidr.Mask.Size()
	switch ipFamily {
	case "IPv4":
		if length != 24 {
			return nil, fmt.Errorf("ipv4 setup needs vpn network to have /24 subnet mask, got %d", length)
		}
	case "IPv6":
		if length != 120 {
			return nil, fmt.Errorf("ipv6 setup needs vpn network to have /120 subnet mask, got %d", length)
		}
	default:
		return nil, fmt.Errorf("unknown ipFamily: %s", ipFamily)
	}
	return cidr, nil
}
