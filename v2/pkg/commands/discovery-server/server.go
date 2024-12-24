package discoveryserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	_ "embed"

	"github.com/forestnode-io/oneshot/v2/pkg/configuration"
	"github.com/forestnode-io/oneshot/v2/pkg/events"
	"github.com/forestnode-io/oneshot/v2/pkg/log"
	"github.com/forestnode-io/oneshot/v2/pkg/net/webrtc/signallingserver/proto"
	"github.com/forestnode-io/oneshot/v2/pkg/output"
	oneshotfmt "github.com/forestnode-io/oneshot/v2/pkg/output/fmt"
	"github.com/forestnode-io/oneshot/v2/pkg/ssl"
	"github.com/pion/webrtc/v3"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

var kaep = keepalive.EnforcementPolicy{
	MinTime: 3 * time.Second, // If a client pings more than once every 3 seconds, terminate the connection
}

var kasp = keepalive.ServerParameters{
	MaxConnectionIdle:     9 * time.Second, // If a client is idle for 6 seconds, send a GOAWAY
	MaxConnectionAgeGrace: 1 * time.Second, // Allow 1 seconds for pending RPCs to complete before forcibly closing connections
	Time:                  3 * time.Second, // Ping the client if it is idle for 5 seconds to ensure the connection is still active
	Timeout:               1 * time.Second, // Wait 1 second for the ping ack before assuming the connection is dead
}

type requestBundle struct {
	w         http.ResponseWriter
	r         *http.Request
	sessionID string
	done      chan struct{}
}

type server struct {
	os *oneshotServer

	pendingSessionID string
	assignedURL      string

	rtcConfig *webrtc.Configuration
	config    *configuration.Root
	scheme    string

	errorPageTitle string

	queue chan requestBundle
	mu    sync.Mutex

	proto.UnimplementedSignallingServerServer
}

func newServer(c *configuration.Root) (*server, error) {
	config := c.Subcommands.DiscoveryServer
	p2pConfig := c.NATTraversal.P2P
	if p2pConfig.WebRTCConfiguration == nil {
		return nil, output.UsageErrorF("p2p configuration is nil")
	}

	iwc, err := p2pConfig.ParseConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to parse p2p configuration: %w", err)
	}
	rc, err := iwc.WebRTCConfiguration()
	if err != nil {
		return nil, fmt.Errorf("failed to get WebRTC configuration: %w", err)
	}

	s := server{
		queue:     make(chan requestBundle, config.MaxClientQueueSize),
		rtcConfig: rc,
		config:    c,
		scheme:    config.URLAssignment.Scheme,
	}
	if s.scheme == "" {
		if c.Server.IsUsingTLS() {
			s.scheme = "https"
		} else {
			s.scheme = "http"
		}
	}

	return &s, nil
}

func (s *server) run(ctx context.Context) error {
	log := zerolog.Ctx(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		l   net.Listener
		err error

		config = s.config.Subcommands.DiscoveryServer

		dc = config.APIServer
		hc = s.config.Server
	)

	if dc.TLSCert != "" && dc.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(dc.TLSCert, dc.TLSKey)
		if err != nil {
			return fmt.Errorf("unable to load tls key pair: %w", err)
		}
		l, err = tls.Listen("tcp", dc.Addr, &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
		if err != nil {
			return fmt.Errorf("unable to listen for tls traffic on %s: %w", dc.Addr, err)
		}
	} else {
		l, err = net.Listen("tcp", dc.Addr)
		if err != nil {
			return fmt.Errorf("unable to listen for traffic on %s: %w", dc.Addr, err)
		}
	}

	log.Info().
		Str("addr", dc.Addr).
		Msg("listening for api traffic")

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHTTP)
	hs := http.Server{
		Addr:    oneshotfmt.Address(hc.Host, hc.Port),
		Handler: mux,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	defer func() {
		wg.Wait()
		events.Stop(ctx)
	}()

	go func() {
		defer wg.Done()
		<-ctx.Done()
		log.Info().Msg("shutting down")

		ctx, cancel := context.WithTimeout(context.Background(), 5)
		defer cancel()

		if s.os != nil {
			s.os.Close()
		}

		if err := hs.Shutdown(ctx); err != nil {
			log.Error().Err(err).
				Msg("error shutting down http server")
		}

		log.Info().Msg("http service shutdown")

		if err := l.Close(); err != nil {
			log.Error().Err(err).
				Msg("error closing listener")
		}

		log.Info().Msg("discovery service shutdown")
	}()

	if hc.IsUsingTLS() {
		tc, err := ssl.GetTLSConfig(hc.TLS)
		if err != nil {
			return fmt.Errorf("failed to get tls config: %w", err)
		}
		hs.TLSConfig = tc
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		// TODO: figure how to use tls with in memory certs
		if err := hs.ListenAndServe(); err != nil {
			cancel()
			if err != http.ErrServerClosed {
				log.Error().Err(err).
					Msg("error serving http")
			}
		}
	}()

	go s.worker()

	msg := "listening for http"
	if hc.IsUsingTLS() {
		msg += "s"
	}
	msg += " traffic"
	log.Info().
		Str("addr", hs.Addr).
		Msg(msg)
	server := grpc.NewServer(
		grpc.KeepaliveEnforcementPolicy(kaep),
		grpc.KeepaliveParams(kasp),
	)
	proto.RegisterSignallingServerServer(server, s)
	if err := server.Serve(l); err != nil {
		if !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("error serving grpc: %w", err)
		}
	}

	return nil
}

func (s *server) queueRequest(sessionID string, w http.ResponseWriter, r *http.Request) (<-chan struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var (
		currentClientQueueCount = len(s.queue)
		maxClientQueueCount     = cap(s.queue)
	)
	if maxClientQueueCount <= currentClientQueueCount {
		return nil, ErrClientQueueFull
	}

	done := make(chan struct{})
	s.queue <- requestBundle{
		w:         w,
		r:         r,
		sessionID: sessionID,
		done:      done,
	}

	return done, nil
}

func (s *server) handleURLRequest(rurl string, required bool) (string, error) {
	var (
		config   = s.config.Subcommands.DiscoveryServer
		uaConfig = config.URLAssignment
		scheme   = uaConfig.Scheme
		domain   = uaConfig.Domain + fmt.Sprintf(":%d", config.URLAssignment.Port)
		upath    = path.Join(uaConfig.PathPrefix, uaConfig.Path)
	)

	if rurl == "" {
		if required {
			return "", errors.New("no url provided")
		}
		u := url.URL{
			Scheme: scheme,
			Host:   domain,
			Path:   upath,
		}
		s.assignedURL = strings.TrimSuffix(u.String(), "/")
		return s.assignedURL, nil
	}

	u, err := url.Parse(rurl)
	if err != nil {
		return "", fmt.Errorf("invalid url: %w", err)
	}
	u.Scheme = scheme
	u.Host = domain
	u.Path = path.Join(uaConfig.PathPrefix, u.Path)
	if u.String() != rurl && required {
		return "", nil
	}

	s.assignedURL = strings.TrimSuffix(u.String(), "/")

	return rurl, nil
}

func (s *server) Connect(stream proto.SignallingServer_ConnectServer) error {
	var (
		log    = log.Logger()
		ctx    = log.WithContext(stream.Context())
		config = s.config.Subcommands.DiscoveryServer
	)

	log.Debug().Msg("new connection")

	if s.os != nil {
		log.Debug().
			Msg("got connection while another is in progress")

		return errors.New("already connected")
	}

	var (
		resetPending = func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.pendingSessionID = ""
		}
		err error
	)
	s.os, err = newOneshotServer(ctx, config.RequiredKey.Value, stream, resetPending, s.handleURLRequest)
	if err != nil {
		log.Error().Err(err).
			Msg("error creating oneshot server")
		return err
	}
	log.Debug().Msg("new oneshot server arrival")

	// hold the stream open until the oneshot server is done.
	// from this point on, the http server will be the only thing
	// using the stream, we just need to hold it open here.
	select {
	case <-ctx.Done():
	case <-s.os.done:
	}
	log.Debug().Msg("oneshot server disconnected")
	s.os = nil
	s.pendingSessionID = ""

	return nil
}
