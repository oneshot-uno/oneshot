package tcp

import (
	"net"
	"time"
)

type Listener struct {
	*net.TCPListener
}

func UpgradeListener(l net.Listener) (net.Listener, error) {
	tcpListener, ok := l.(*net.TCPListener)
	if !ok {
		return nil, net.UnknownNetworkError("TCP is required")
	}

	return Listener{tcpListener}, nil
}

func (ln Listener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
