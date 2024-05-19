package signallingserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/forestnode-io/oneshot/v2/pkg/net/webrtc/signallingserver/headers"
	"github.com/forestnode-io/oneshot/v2/pkg/net/webrtc/signallingserver/messages"
	"github.com/forestnode-io/oneshot/v2/pkg/net/webrtc/signallingserver/proto"
	"github.com/rs/zerolog"
	"golang.org/x/mod/semver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

var ErrClosedByUser = errors.New("closed by user")

var kacp = keepalive.ClientParameters{
	Time:    6 * time.Second, // send pings every 6 seconds if there is no activity
	Timeout: time.Second,     // wait 1 second for ping ack before considering the connection dead
}
var dialTimeout = 3 * time.Second

type discoveryServerKey struct{}

type DiscoveryServer struct {
	conn          *grpc.ClientConn
	stream        proto.SignallingServer_ConnectClient
	AssignedURL   string
	config        *DiscoveryServerConfig
	arrival       *messages.ServerArrivalRequest
	doneFunc      func()
	AcceptsReport bool
}

func (d *DiscoveryServer) Stream() proto.SignallingServer_ConnectClient {
	return d.stream
}

type DiscoveryServerConfig struct {
	Enabled                   bool
	URL                       string
	Key                       string
	Insecure                  bool
	TLSCert                   string
	TLSKey                    string
	SendReports               bool
	HeaderBlockList           []string
	HeaderAllowList           []string
	UseDefaultHeaderBlockList bool

	VersionInfo messages.VersionInfo
}

func WithDiscoveryServer(ctx context.Context) (context.Context, <-chan struct{}) {
	doneChan := make(chan struct{})
	ds := &DiscoveryServer{
		doneFunc: func() {
			close(doneChan)
		},
	}
	return context.WithValue(ctx, discoveryServerKey{}, &ds), doneChan
}

// ConnectToDiscoveryServer connects to the discovery server and sends a handshake.
// The connection is kept open and stuffed into the context.
func ConnectToDiscoveryServer(ctx context.Context, c *DiscoveryServerConfig) error {
	dds, ok := ctx.Value(discoveryServerKey{}).(**DiscoveryServer)
	if !ok || dds == nil {
		return nil
	}

	defer func() {
		if (*dds).config == nil {
			(*dds).config = c
		}
	}()

	if !c.Enabled {
		return nil
	}

	ctx = context.WithoutCancel(ctx)
	log := zerolog.Ctx(ctx)

	log.Debug().Msg("connecting to discovery server")
	conn, err := getConnectionToDiscoveryServer(ctx, c)
	if err != nil {
		return fmt.Errorf("failed to connect to discovery server: %w", err)
	}

	log.Debug().Msg("opening bidirectional stream to discovery server")
	ds, err := newDiscoveryServer(ctx, c, conn)
	if err != nil {
		return fmt.Errorf("failed to create discovery server: %w", err)
	}
	ds.config = c
	ds.doneFunc = (*dds).doneFunc
	*dds = ds
	return nil
}

func SendArrivalToDiscoveryServer(ctx context.Context, arrival *messages.ServerArrivalRequest) error {
	ds := GetDiscoveryServer(ctx)
	if ds == nil {
		return nil
	}
	if !ds.config.Enabled {
		return nil
	}

	ctx = context.WithoutCancel(ctx)
	log := zerolog.Ctx(ctx)

	log.Debug().Msg("negotiating arrival with discovery server")

	ds.arrival = arrival

	return ds.negotiateArrival(ctx, arrival)
}

func GetDiscoveryServer(ctx context.Context) *DiscoveryServer {
	dds, ok := ctx.Value(discoveryServerKey{}).(**DiscoveryServer)
	if !ok {
		return nil
	}
	return *dds
}

func SendReportToDiscoveryServer(ctx context.Context, report *messages.Report) {
	ds := GetDiscoveryServer(ctx)
	if ds == nil {
		return
	}

	if !ds.config.Enabled {
		return
	}

	if !ds.AcceptsReport || !ds.config.SendReports {
		return
	}

	filter := defaultBlockHeaders
	if !ds.config.UseDefaultHeaderBlockList {
		filter = nil
	}
	filter = mergeBlockList(filter, ds.config.HeaderAllowList, ds.config.HeaderBlockList)

	if report.Success != nil {
		if report.Success.Request != nil {
			if report.Success.Request.Header != nil {
				for _, header := range filter {
					delete(report.Success.Request.Header, header)
				}
			}
		}
		if report.Success.Response != nil {
			if report.Success.Response.Header != nil {
				for _, header := range filter {
					delete(report.Success.Response.Header, header)
				}
			}
		}
	}
	for _, attempt := range report.Attempts {
		if attempt.Request != nil {
			if attempt.Request.Header != nil {
				for _, header := range filter {
					delete(attempt.Request.Header, header)
				}
			}
		}
		if attempt.Response != nil {
			if attempt.Response.Header != nil {
				for _, header := range filter {
					delete(attempt.Response.Header, header)
				}
			}
		}
	}

	ctx = context.WithoutCancel(ctx)
	log := zerolog.Ctx(ctx)
	if err := Send(ds, report); err != nil {
		log.Error().Err(err).
			Msg("failed to send report to discovery server")
	} else {
		log.Debug().Msg("sent report to discovery server")
	}
}

func CloseDiscoveryServer(ctx context.Context) error {
	ds := GetDiscoveryServer(ctx)
	if ds == nil {
		return nil
	}
	if !ds.config.Enabled {
		return nil
	}
	return ds.Close()
}

func (d *DiscoveryServer) send(m messages.Message) error {
	env, err := messages.ToRPCEnvelope(m)
	if err != nil {
		return fmt.Errorf("failed to convert message to RPC envelope: %w", err)
	}
	return d.stream.Send(env)
}

func (d *DiscoveryServer) recv() (messages.Message, error) {
	env, err := d.stream.Recv()
	if err != nil {
		// check if the discovery server closed the connection by user request
		if errors.Is(err, io.EOF) {
			trailer := d.stream.Trailer()
			values := trailer.Get(headers.ClosedByUser)
			if len(values) > 0 {
				v := values[0]
				if v == "true" {
					return nil, ErrClosedByUser
				}
			}
		}
		return nil, fmt.Errorf("failed to receive message from discovery server: %w", err)
	}
	m, err := messages.FromRPCEnvelope(env)
	if err != nil {
		return nil, fmt.Errorf("failed to convert RPC envelope to message: %w", err)
	}
	return m, nil
}

func (d *DiscoveryServer) negotiateArrival(ctx context.Context, arrival *messages.ServerArrivalRequest) error {
	var (
		log  = zerolog.Ctx(ctx)
		conf = d.config

		closeConn = true
	)
	defer func() {
		if closeConn {
			d.Close()
		}
	}()

	log.Debug().
		Msg("sending handshake to discovery server")
	err := Send(d, &messages.Handshake{
		ID:          conf.Key,
		VersionInfo: conf.VersionInfo,
	})
	if err != nil {
		return fmt.Errorf("failed to send handshake to discovery server: %w", err)
	}

	log.Debug().
		Msg("waiting for discovery server to respond to handshake")

	// Receive the handshake response with a timeout.
	// We probably only really need a timeout on the first message.

	type hserr struct {
		err error
		hs  *messages.Handshake
	}
	hserrChan := make(chan hserr, 1)
	go func() {
		hs, err := Receive[*messages.Handshake](d)
		hserrChan <- hserr{err: err, hs: hs}
		close(hserrChan)
	}()

	var hs *messages.Handshake
	select {
	case <-time.After(1 * time.Second):
		return ErrHandshakeTimeout
	case <-ctx.Done():
		return ctx.Err()
	case hserr := <-hserrChan:
		if hserr.err != nil {
			return fmt.Errorf("failed to receive handshake from discovery server: %w", hserr.err)
		}
		if hserr.hs.Error != "" {
			return fmt.Errorf("discovery server returned error: %s", hserr.hs.Error)
		}
		hs = hserr.hs
	}

	log.Debug().
		Str("version", hs.VersionInfo.Version).
		Str("api-version: ", hs.VersionInfo.APIVersion).
		Msg("discovery server handshake successful")

	// Check if the discovery server is running a newer version of the API than this client.
	// The discovery server should be backwards compatible with older clients.
	if semver.Compare(hs.VersionInfo.APIVersion, conf.VersionInfo.APIVersion) < 0 {
		return fmt.Errorf("discovery server is running an older version of the API (%s) than this client (%s)", hs.VersionInfo.APIVersion, conf.VersionInfo.APIVersion)
	}

	log.Debug().
		Interface("arrival-request", arrival).
		Msg("sending server arrival request")

	if err = Send(d, arrival); err != nil {
		return fmt.Errorf("failed to send server arrival request to discovery server: %w", err)
	}

	// Wait for the discovery server to acknowledge the arrival.
	log.Debug().Msg("waiting for discovery server to acknowledge arrival")
	sar, err := Receive[*messages.ServerArrivalResponse](d)
	if err != nil {
		return fmt.Errorf("failed to receive server arrival response from discovery server: %w", err)
	}
	if sar.Error != "" {
		return fmt.Errorf("discovery server returned error: %s", sar.Error)
	}
	if sar.AssignedURL == "" {
		return fmt.Errorf("discovery server did not assign a URL")
	}

	closeConn = false
	d.AssignedURL = sar.AssignedURL
	d.AcceptsReport = sar.AcceptsReport
	log.Debug().Msg("discovery server acknowledged arrival")
	log.Info().
		Str("assigned-url", d.AssignedURL).
		Msg("negotiated arrival with discovery server")

	return nil
}

func (d *DiscoveryServer) Close() error {
	if !d.config.Enabled {
		return nil
	}
	d.stream.CloseSend()
	return d.conn.Close()
}

func Send[M messages.Message](d *DiscoveryServer, m M) error {
	return d.send(m)
}

func Receive[M messages.Message](d *DiscoveryServer) (M, error) {
	var (
		m   M
		mi  messages.Message
		err error
	)

	mi, err = d.recv()
	if err != nil {
		return m, err
	}

	m, ok := mi.(M)
	if !ok {
		return m, fmt.Errorf("expected message of type %T but got %T", m, mi)
	}

	return m, nil
}

func ReconnectDiscoveryServer(ctx context.Context) error {
	ds := GetDiscoveryServer(ctx)
	if ds == nil {
		return nil
	}
	if !ds.config.Enabled {
		return nil
	}
	ds.conn.Close()

	ctx = context.WithoutCancel(ctx)
	log := zerolog.Ctx(ctx)
	config := ds.config
	arrival := ds.arrival
	arrival.PreviouslyAssignedURL = ds.AssignedURL

	log.Debug().Msg("connecting to discovery server")
	conn, err := getConnectionToDiscoveryServer(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to connect to discovery server: %w", err)
	}

	log.Debug().Msg("opening bidirectional stream to discovery server")
	newDS, err := newDiscoveryServer(ctx, config, conn)
	if err != nil {
		return fmt.Errorf("failed to create discovery server: %w", err)
	}
	newDS.arrival = arrival

	log.Debug().Msg("negotiating arrival with discovery server")
	if err := newDS.negotiateArrival(ctx, arrival); err != nil {
		return fmt.Errorf("failed to negotiate arrival with discovery server: %w", err)
	}

	*ds = *newDS

	return nil
}

func getConnectionToDiscoveryServer(ctx context.Context, config *DiscoveryServerConfig) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(kacp),
		grpc.FailOnNonTempDialError(true),
	}

	if config.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		if config.TLSCert != "" {
			if config.TLSKey == "" {
				return nil, fmt.Errorf("missing TLS key")
			}
		}
		if config.TLSKey != "" {
			if config.TLSCert == "" {
				return nil, fmt.Errorf("missing TLS cert")
			}
		}

		var tlsConf *tls.Config
		if config.TLSCert != "" && config.TLSKey != "" {
			cert, err := tls.LoadX509KeyPair(config.TLSCert, config.TLSKey)
			if err != nil {
				return nil, fmt.Errorf("failed to load TLS keypair: %w", err)
			}
			tlsConf = &tls.Config{
				Certificates: []tls.Certificate{cert},
			}
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
	}

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	return grpc.DialContext(dialCtx, config.URL, opts...)
}

func newDiscoveryServer(ctx context.Context, config *DiscoveryServerConfig, conn *grpc.ClientConn) (*DiscoveryServer, error) {
	stream, err := proto.NewSignallingServerClient(conn).Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to discovery server: %w", err)
	}

	return &DiscoveryServer{
		conn:   conn,
		stream: stream,
		config: config,
	}, nil
}

var ErrHandshakeTimeout = errors.New("handshake timed out")

var defaultBlockHeaders = []string{
	"Authorization",
	"Cookie",
	"Set-Cookie",
	"WWW-Authenticate",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"X-Api-Key",
	"X-Auth-Token",
	"Bearer",
	"X-Csrf-Token",
	"X-XSRF-TOKEN",
	"X-Access-Token",
	"X-Refresh-Token",
	"X-User-ID",
	"X-User-Name",
	"X-Identity-Provider",
	"X-SSH-Key",
	"Sec-Token-Binding",
	"Digest",
	"X-Alt-Referer",
	"X-Password",
}

func mergeBlockList(defaults []string, allow, block []string) []string {
	headerMap := make(map[string]struct{})

	for _, header := range defaults {
		headerMap[header] = struct{}{}
	}

	for _, header := range block {
		headerMap[header] = struct{}{}
	}

	// Remove headers from the allowlist
	for _, header := range allow {
		delete(headerMap, header)
	}

	// Convert map keys to a slice
	finalList := make([]string, 0, len(headerMap))
	for header := range headerMap {
		finalList = append(finalList, header)
	}

	return finalList
}
