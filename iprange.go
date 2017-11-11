package dnrt

import (
	"errors"
	"net"
	"strings"
)

type IPRange struct {
	ip    net.IP
	ipNet *net.IPNet
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (r *IPRange) GetAll() (ips []net.IP, err error) {
	if r.ipNet == nil {
		ips = append(ips, r.ip)
		return ips, nil
	}

	for ip := r.ip.Mask(r.ipNet.Mask); r.ipNet.Contains(ip); incrementIP(ip) {
		newIP := make(net.IP, len(ip))
		copy(newIP, ip)
		ips = append(ips, newIP)
	}

	if len(ips) == 0 {
		return ips, errors.New("can't get ip list")
	}

	return ips[1 : len(ips)-1], nil
}

func getRangeByString(str string) (rng IPRange, err error) {
	if strings.Contains(str, "/") {
		ip, ipNet, err := net.ParseCIDR(str)
		return IPRange{ip: ip, ipNet: ipNet}, err
	}

	ip := net.ParseIP(str)
	return IPRange{ip: ip, ipNet: nil}, err
}
