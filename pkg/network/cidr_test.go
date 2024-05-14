package network

import "testing"

func Test_ValidateCIDR(t *testing.T) {
	tt := []struct {
		name        string
		networkCIDR string
		ipFamily    string
		wantError   bool
	}{
		{
			name:        "ipv4 valid cidr",
			networkCIDR: "192.168.0.0/24",
			ipFamily:    "IPv4",
		},

		{
			name:        "ipv4 invalid cidr",
			networkCIDR: "192.168.0.0/26",
			ipFamily:    "IPv4",
			wantError:   true,
		},

		{
			name:        "ipv6 valid subnet mask",
			networkCIDR: "fd8f:6d53:b97a:1::/120",
			ipFamily:    "IPv6",
		},

		{
			name:        "ipv4 invalid subnet mask",
			networkCIDR: "fd8f:6d53:b97a:1::/121",
			ipFamily:    "IPv6",
			wantError:   true,
		},

		{
			name:        "invalid ip",
			networkCIDR: "ajwdawjkdjawd",
			wantError:   true,
		},
	}
	for _, testcase := range tt {
		t.Run(testcase.name, func(t *testing.T) {
			_, err := ValidateCIDR(testcase.networkCIDR, testcase.ipFamily)
			if testcase.wantError && err == nil {
				t.Fatal("want error, got nil")
			}
			if err != nil && !testcase.wantError {
				t.Fatalf("got unwanted err: %s", err)
			}
		})
	}
}
