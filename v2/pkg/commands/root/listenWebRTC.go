package root

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/forestnode-io/oneshot/v2/pkg/configuration"
	"github.com/forestnode-io/oneshot/v2/pkg/net/webrtc/sdp/signallers"
	"github.com/forestnode-io/oneshot/v2/pkg/net/webrtc/server"
	"github.com/forestnode-io/oneshot/v2/pkg/net/webrtc/signallingserver"
	"github.com/rs/zerolog"
)

func (r *rootCommand) listenWebRTC(ctx context.Context, bat, portMapAddr string, iceGatherTimeout time.Duration) error {
	r.wg.Add(1)
	defer r.wg.Done()

	var (
		log = zerolog.Ctx(ctx)
	)

	err := r.configureWebRTC()
	if err != nil {
		return fmt.Errorf("failed to configure p2p: %w", err)
	}

	signaller, local, err := getSignaller(ctx, r.config, portMapAddr)
	if err != nil {
		return fmt.Errorf("failed to get p2p signaller: %w", err)
	}
	defer signaller.Shutdown()

	if !local && !r.config.Discovery.Enabled {
		return errors.New("discovery is not enabled")
	}

	// create a webrtc server with the same handler as the http server
	a := server.NewServer(r.webrtcConfig, bat, iceGatherTimeout, http.HandlerFunc(r.server.ServeHTTP))
	defer a.Wait()

	log.Info().Msg("starting p2p discovery mechanism")

	for {
		if err := signaller.Start(ctx, a); err != nil {
			if errors.Is(err, signallingserver.ErrClosedByUser) {
				log.Error().Err(err).
					Msg("error starting p2p discovery mechanism")
				return err
			}

			if strings.Contains(err.Error(), "context canceled") {
				return nil
			}

			log.Warn().
				Err(err).
				Msg("reconnecting to discovery server")

			if local {
				continue
			}

			time.Sleep(200 * time.Millisecond)
			if err = signallingserver.ReconnectDiscoveryServer(ctx); err != nil {
				if errors.Is(err, signallingserver.ErrHandshakeTimeout) {
					continue
				}

				log.Error().Err(err).
					Msg("error starting p2p discovery mechanism")
				return fmt.Errorf("failed to reconnect to discovery server: %w", err)
			}
			continue
		}

		return nil
	}
}

func getSignaller(ctx context.Context, config *configuration.Root, portMapAddr string) (signallers.ServerSignaller, bool, error) {
	var (
		dsConf              = config.Discovery
		p2pConf             = config.NATTraversal.P2P
		webRTCSignallingURL = dsConf.Addr
		webRTCSignallingDir = p2pConf.DiscoveryDir
	)

	if webRTCSignallingDir != "" {
		if config == nil {
			return nil, false, fmt.Errorf("nil p2p configuration")
		}
		iwc, err := p2pConf.ParseConfig()
		if err != nil {
			return nil, false, fmt.Errorf("failed to parse p2p configuration: %w", err)
		}
		wc, err := iwc.WebRTCConfiguration()
		if err != nil {
			return nil, false, fmt.Errorf("failed to get WebRTC configuration: %w", err)
		}
		return signallers.NewFileServerSignaller(webRTCSignallingDir, wc), true, nil
	} else if webRTCSignallingURL != "" {
		return signallers.NewServerServerSignaller(), false, nil
	}

	return nil, false, fmt.Errorf("no p2p discovery mechanism specified")
}

func (r *rootCommand) configureWebRTC() error {
	conf := r.config.NATTraversal.P2P
	if len(conf.WebRTCConfiguration) == 0 {
		return nil
	}

	iwc, err := conf.ParseConfig()
	if err != nil {
		return fmt.Errorf("failed to parse p2p configuration: %w", err)
	}
	wc, err := iwc.WebRTCConfiguration()
	if err != nil {
		return fmt.Errorf("failed to get WebRTC configuration: %w", err)
	}
	r.webrtcConfig = wc

	return nil
}
