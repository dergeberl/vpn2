package app

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func Test_computeShootTargetAndAddr(t *testing.T) {
	type want struct {
		subnet net.IPNet
		target net.IP
	}
	tt := []struct {
		name       string
		vpnNetwork net.IPNet
		want       want
	}{
		{
			name: "ipv4 with /24",
			vpnNetwork: net.IPNet{
				IP:   net.IPv4(192, 168, 123, 0),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			want: want{
				subnet: net.IPNet{
					IP: net.IPv4(192, 168, 123, 194),
					// /26
					Mask: net.IPv4Mask(255, 255, 255, 192),
				},
				target: net.IPv4(192, 168, 123, 193),
			},
		},
	}
	for _, testcase := range tt {
		t.Run(testcase.name, func(t *testing.T) {

			subnet, target := computeShootAddrAndTargets(&testcase.vpnNetwork, 0)
			if !target.Equal(testcase.want.target) {
				t.Errorf("want: %+v, got: %+v", testcase.want.target, *target)
			}

			if !bytes.Equal(subnet.Mask, testcase.want.subnet.Mask) {
				t.Errorf("unequal subnet masks: want: %s, got: %s", testcase.want.subnet.Mask, subnet.Mask)
			}

			if !subnet.IP.Equal(testcase.want.subnet.IP) {
				t.Errorf("unequal subnet ip: want: %+v, got: %+v", testcase.want.subnet.IP, subnet.IP)
			}
		})
	}
}

func Test_computeSeedTargetAndAddr(t *testing.T) {
	type want struct {
		subnet  net.IPNet
		targets []net.IP
	}
	tt := []struct {
		name         string
		vpnNetwork   net.IPNet
		acquiredIP   net.IP
		haVPNClients int
		want         want
	}{
		{
			name:       "ipv4 with /24",
			acquiredIP: net.ParseIP("192.1.0.1"),
			vpnNetwork: net.IPNet{
				IP:   net.IPv4(192, 168, 123, 0),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			haVPNClients: 2,
			want: want{
				subnet: net.IPNet{
					// acquiredIP
					IP: net.ParseIP("192.1.0.1"),
					// /26
					Mask: net.IPv4Mask(255, 255, 255, 192),
				},
				targets: []net.IP{
					net.IPv4(192, 168, 123, 194),
					net.IPv4(192, 168, 123, 195),
				},
			},
		},
	}
	for _, testcase := range tt {
		t.Run(testcase.name, func(t *testing.T) {
			subnet, targets := computeSeedTargetAndAddr(testcase.acquiredIP, &testcase.vpnNetwork, testcase.haVPNClients)
			for i, target := range targets {
				if !target.Equal(testcase.want.targets[i]) {
					t.Errorf("unequal targets at index %d: want: %+v, got: %+v", i, testcase.want.targets[i], target)
				}
			}

			if !reflect.DeepEqual(*subnet, testcase.want.subnet) {
				t.Fatalf("want: %+v, got: %+v", testcase.want.subnet, *subnet)
			}
		})
	}
}
