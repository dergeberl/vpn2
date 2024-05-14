package network

import (
	"net"
	"slices"
)

const (
	bondBits  = 26
	bondStart = 192
)

// please change this name omg
func ComputeShootAddrAndTargets(vpnNetwork *net.IPNet, vpnClientIndex int) (*net.IPNet, []net.IP) {
	_, addrLen := vpnNetwork.Mask.Size()

	clientIP := ClientIP(vpnNetwork, vpnClientIndex)

	shootSubnet := &net.IPNet{
		IP:   clientIP,
		Mask: net.CIDRMask(bondBits, addrLen),
	}

	target := slices.Clone(clientIP)
	target[3] = byte(bondStart + 1)

	return shootSubnet, append([]net.IP{}, target)
}

// please change this name omg
func ComputeSeedAddrAndTargets(acquiredIP net.IP, vpnNetwork *net.IPNet, haVPNClients int) (*net.IPNet, []net.IP) {
	subnet := &net.IPNet{
		IP:   acquiredIP,
		Mask: net.CIDRMask(bondBits, 32),
	}

	targets := make([]net.IP, 0, haVPNClients)
	for i := range haVPNClients {
		targets = append(targets, ClientIP(vpnNetwork, i))
	}
	return subnet, targets
}

func ClientIP(vpnNetwork *net.IPNet, index int) net.IP {
	newIP := slices.Clone(vpnNetwork.IP.To4())
	newIP[3] = byte(bondStart + 2 + index)
	return newIP
}
