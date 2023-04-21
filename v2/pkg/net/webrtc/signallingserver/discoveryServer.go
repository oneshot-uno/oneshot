package signallingserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/oneshot-uno/oneshot/v2/pkg/net/webrtc/signallingserver/messages"
	"github.com/oneshot-uno/oneshot/v2/pkg/net/webrtc/signallingserver/proto"
	"github.com/rs/zerolog"
	"golang.org/x/mod/semver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

var kacp = keepalive.ClientParameters{
	Time:    6 * time.Second, // send pings every 6 seconds if there is no activity
	Timeout: time.Second,     // wait 1 second for ping ack before considering the connection dead
}
var dialTimeout = 3 * time.Second

type discoveryServerKey struct{}

type DiscoveryServer struct {
	conn        *grpc.ClientConn
	stream      proto.SignallingServer_ConnectClient
	AssignedURL string
}

type DiscoveryServerConfig struct {
	URL      string
	Key      string
	Insecure bool
	TLSCert  string
	TLSKey   string

	VersionInfo messages.VersionInfo
}

func WithDiscoveryServer(ctx context.Context, c DiscoveryServerConfig, arrival messages.ServerArrivalRequest) (context.Context, error) {
	log := zerolog.Ctx(ctx)
	opts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(kacp),
		grpc.FailOnNonTempDialError(true),
	}
	if c.Insecure {
		log.Debug().Msg("using insecure gRPC connection")
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		if c.TLSCert != "" {
			if c.TLSKey == "" {
				return ctx, fmt.Errorf("missing TLS key")
			}
		}
		if c.TLSKey != "" {
			if c.TLSCert == "" {
				return ctx, fmt.Errorf("missing TLS cert")
			}
		}

		var tlsConf *tls.Config
		if c.TLSCert != "" && c.TLSKey != "" {
			log.Debug().Msg("using custom TLS keypair for gRPC connection")
			cert, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
			if err != nil {
				return ctx, fmt.Errorf("failed to load TLS keypair: %w", err)
			}
			tlsConf = &tls.Config{
				Certificates: []tls.Certificate{cert},
			}
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
	}

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	log.Debug().Msg("dialing discovery server")
	conn, err := grpc.DialContext(dialCtx, c.URL, opts...)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return ctx, fmt.Errorf("timeout dialing discovery server")
		}
		if errors.Is(err, context.Canceled) {
			return ctx, fmt.Errorf("canceled dialing discovery server")
		}
		return ctx, fmt.Errorf("failed to dial discovery server: %w", err)
	}

	log.Debug().Msg("opening gRPC stream to discovery server")
	stream, err := proto.NewSignallingServerClient(conn).Connect(ctx)
	if err != nil {
		conn.Close()
		return ctx, fmt.Errorf("failed to connect to discovery server: %w", err)
	}

	ds := DiscoveryServer{
		conn:   conn,
		stream: stream,
	}

	log.Debug().Msg("sending handshake to discovery server")
	err = Send(&ds, &messages.Handshake{
		ID:          c.Key,
		VersionInfo: c.VersionInfo,
	})
	if err != nil {
		ds.Close()
		return ctx, fmt.Errorf("failed to send handshake to discovery server: %w", err)
	}

	log.Debug().Msg("waiting for discovery server to respond to handshake")
	hs, err := Receive[*messages.Handshake](&ds)
	if err != nil {
		ds.Close()
		return ctx, fmt.Errorf("failed to receive handshake from discovery server: %w", err)
	}
	if hs.Error != "" {
		ds.Close()
		return ctx, fmt.Errorf("discovery server returned error: %s", hs.Error)
	}
	log.Debug().
		Str("version", hs.VersionInfo.Version).
		Str("api-version: ", hs.VersionInfo.APIVersion).
		Msg("discovery server handshake successful")

	// Check if the discovery server is running a newer version of the API than this client.
	// The discovery server should be backwards compatible with older clients.
	if semver.Compare(hs.VersionInfo.APIVersion, c.VersionInfo.APIVersion) < 0 {
		ds.Close()
		return ctx, fmt.Errorf("discovery server is running an older version of the API (%s) than this client (%s)", hs.VersionInfo.APIVersion, c.VersionInfo.APIVersion)
	}

	log.Debug().
		Interface("arrival-request", arrival).
		Msg("sending server arrival request")

	if err = Send(&ds, &arrival); err != nil {
		ds.Close()
		return ctx, fmt.Errorf("failed to send server arrival request to discovery server: %w", err)
	}

	// Wait for the discovery server to acknowledge the arrival.
	log.Debug().Msg("waiting for discovery server to acknowledge arrival")
	sar, err := Receive[*messages.ServerArrivalResponse](&ds)
	if err != nil {
		ds.Close()
		return ctx, fmt.Errorf("failed to receive server arrival response from discovery server: %w", err)
	}
	if sar.Error != "" {
		ds.Close()
		return ctx, fmt.Errorf("discovery server returned error: %s", sar.Error)
	}
	if sar.AssignedURL == "" {
		ds.Close()
		return ctx, fmt.Errorf("discovery server did not assign a URL")
	}

	ds.AssignedURL = sar.AssignedURL
	log.Debug().Msg("discovery server acknowledged arrival")
	log.Info().
		Str("assigned-url", ds.AssignedURL).
		Msg("discovery server assigned url")

	return context.WithValue(ctx, discoveryServerKey{}, &ds), nil
}

func GetDiscoveryServer(ctx context.Context) *DiscoveryServer {
	ds, ok := ctx.Value(discoveryServerKey{}).(*DiscoveryServer)
	if !ok {
		return nil
	}
	return ds
}

func CloseDiscoveryServer(ctx context.Context) error {
	ds := GetDiscoveryServer(ctx)
	if ds == nil {
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
		return nil, fmt.Errorf("failed to receive message from discovery server: %w", err)
	}
	m, err := messages.FromRPCEnvelope(env)
	if err != nil {
		return nil, fmt.Errorf("failed to convert RPC envelope to message: %w", err)
	}
	return m, nil
}

func (d *DiscoveryServer) Close() error {
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
