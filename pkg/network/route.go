package network

import (
	"fmt"
	"net"

	"github.com/go-logr/logr"
	"github.com/vishvananda/netlink"
)

const RT_TABLE_MAIN = 0xfe // = unix.RT_TABLE_MAIN (redefined as not available on not-Linux dev env)

func routeForNetwork(net *net.IPNet, device netlink.Link) netlink.Route {
	// ip route replace $net dev $device
	return netlink.Route{
		Dst:       net,
		Table:     RT_TABLE_MAIN,
		LinkIndex: device.Attrs().Index,
	}
}

func RouteReplace(log logr.Logger, ipnet *net.IPNet, dev netlink.Link) error {
	route := routeForNetwork(ipnet, dev)
	log.Info("replacing route", "route", route, "ipnet", ipnet)
	if err := netlink.RouteReplace(&route); err != nil {
		return fmt.Errorf("error replacing route for %s: %w", ipnet, err)
	}
	return nil
}
