package root

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"

	oneshotnet "github.com/forestnode-io/oneshot/v2/pkg/net"
	"github.com/forestnode-io/oneshot/v2/pkg/net/webrtc/signallingserver"
	"github.com/forestnode-io/oneshot/v2/pkg/net/webrtc/signallingserver/messages"
	"golang.org/x/crypto/bcrypt"
)

func (r *rootCommand) sendArrivalToDiscoveryServer(ctx context.Context, cmd string) error {
	var (
		config   = r.config
		dsConfig = config.Discovery
	)

	if dsConfig.Addr == "" {
		return nil
	}

	arrival := messages.ServerArrivalRequest{
		IsUsingPortMapping: config.NATTraversal.IsUsingUPnP(),
		RedirectOnly:       !config.NATTraversal.P2P.Enabled,
		TTL:                config.Server.Timeout,
		Cmd:                cmd,
	}

	ipThatCanReachDiscoveryServer, err := oneshotnet.GetSourceIP(dsConfig.Addr, 0)
	if err != nil {
		return fmt.Errorf("unable to reach the discovery server: %w", err)
	}
	arrival.Redirect = ipThatCanReachDiscoveryServer

	scheme := "http"
	if config.Server.TLSCert != "" {
		scheme = "https"
	}
	arrival.Redirect = fmt.Sprintf("%s://%s:%d", scheme, arrival.Redirect, config.Server.Port)

	if arrival.IsUsingPortMapping {
		if d := config.NATTraversal.UPnP.Duration; d != 0 && d < arrival.TTL {
			arrival.TTL = d
		}
	}

	if dsConfig.PreferredURL != "" || dsConfig.RequiredURL != "" {
		switch {
		case dsConfig.RequiredURL != "":
			arrival.URL = &messages.SessionURLRequest{
				URL:      dsConfig.RequiredURL,
				Required: true,
			}
		case dsConfig.PreferredURL != "":
			arrival.URL = &messages.SessionURLRequest{
				URL:      dsConfig.PreferredURL,
				Required: false,
			}
		}
	}

	if !arrival.RedirectOnly {
		var (
			baConf   = config.BasicAuth
			username = baConf.Username
			password = baConf.Password
			bam      *messages.BasicAuth
		)

		if username != "" || password != "" {
			bam = &messages.BasicAuth{}
			if username != "" {
				uHash := sha256.Sum256([]byte(username))
				bam.UsernameHash = uHash[:]
			}
			if password != "" {
				pHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				if err != nil {
					return fmt.Errorf("failed to hash password: %w", err)
				}
				bam.PasswordHash = pHash
			}
		}

		arrival.BasicAuth = bam
	}

	hostname, _ := os.Hostname()
	arrival.Hostname = hostname

	return signallingserver.SendArrivalToDiscoveryServer(ctx, &arrival)
}
