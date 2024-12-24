package ssl

import (
	"crypto/tls"
	"net"
)

func UpgradeListener(l net.Listener, config *tls.Config) (net.Listener, error) {
	return tls.NewListener(l, config), nil
}
