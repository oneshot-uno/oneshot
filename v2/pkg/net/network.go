package network

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/forestnode-io/oneshot/v2/pkg/log"
	"github.com/jackpal/gateway"
)

// HostAddresses returns all available ip addresses from all interfaces
func HostAddresses() ([]string, error) {
	ifaceAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	hostAddrs := []string{}
	// run the loop backwards so 127.0.0.1 ends up at the bottom of the list
	for idx := len(ifaceAddrs) - 1; 0 <= idx; idx-- {
		addr := ifaceAddrs[idx].String()
		if strings.Contains(addr, "::") {
			continue
		}

		parts := strings.Split(addr, "/")
		ip := net.ParseIP(parts[0])
		if ip == nil {
			continue
		}

		// Filter out IPv6 address
		if ip.To4() == nil {
			continue
		}

		hostAddrs = append(hostAddrs, ip.String())
	}

	return hostAddrs, nil
}

// GetSourceIP returns the ip address used to access target:port
// If target is the empty string then the default gateway ip is used.
// If the port is 0, then 80 is used by default.
func GetSourceIP(target string, port int) (net.IP, error) {
	if target == "" {
		ip, err := gateway.DiscoverGateway()
		if err != nil {
			return nil, err
		}
		target = ip.String()
	}

	var (
		conn net.Conn
		err  error
	)
	if 0 < port {
		conn, err = net.Dial("udp", fmt.Sprintf("%s:%d", target, port))
	} else {
		conn, err = net.Dial("udp", target)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP, nil
}

func PreferNonPrivateIP(ips []string) (string, string) {
	log := log.Logger()

	if len(ips) == 0 {
		return "", ""
	}

	var (
		preferredAddress net.IP
		port             string
	)

	for _, addr := range ips {
		host, p, err := net.SplitHostPort(addr)
		if err != nil {
			log.Error().Err(err).
				Msg("failed to parse peer address")
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil {
			log.Error().Err(err).
				Msg("failed to parse peer address")
			continue
		}

		if !ip.IsPrivate() {
			preferredAddress = ip
			port = p
			break
		}
	}

	if preferredAddress == nil {
		host, p, err := net.SplitHostPort(ips[0])
		if err != nil {
			log.Error().Err(err).
				Msg("failed to parse peer address")
		} else {
			preferredAddress = net.ParseIP(host)
			port = p
		}
	}

	return preferredAddress.String(), port
}

func AddressParts(add string) (string, string) {
	parts := strings.Split(add, ":")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}

	return parts[0], ""
}

func IsAddressReachable(addr string) bool {
	parts := strings.Split(addr, ":")
	ip := net.ParseIP(parts[0])
	if ip != nil {
		if ip.IsPrivate() {
			return false
		}
	}

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}
