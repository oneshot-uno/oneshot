package receive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/forestnode-io/oneshot/v2/pkg/commands/p2p/client/discovery"
	"github.com/forestnode-io/oneshot/v2/pkg/commands/p2p/client/receive/configuration"
	rootconfig "github.com/forestnode-io/oneshot/v2/pkg/configuration"
	"github.com/forestnode-io/oneshot/v2/pkg/events"
	"github.com/forestnode-io/oneshot/v2/pkg/file"
	oneshotnet "github.com/forestnode-io/oneshot/v2/pkg/net"
	"github.com/forestnode-io/oneshot/v2/pkg/net/webrtc/client"
	"github.com/forestnode-io/oneshot/v2/pkg/net/webrtc/sdp/signallers"
	oneshotos "github.com/forestnode-io/oneshot/v2/pkg/os"
	"github.com/forestnode-io/oneshot/v2/pkg/output"
	"github.com/pion/webrtc/v3"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func New(config *rootconfig.Root) *Cmd {
	return &Cmd{
		config: config,
	}
}

type Cmd struct {
	cobraCommand       *cobra.Command
	fileTransferConfig *file.WriteTransferConfig
	webrtcConfig       *webrtc.Configuration
	config             *rootconfig.Root
}

func (c *Cmd) Cobra() *cobra.Command {
	if c.cobraCommand != nil {
		return c.cobraCommand
	}

	c.cobraCommand = &cobra.Command{
		Use:   "receive [file]",
		Short: "Receive from a sending oneshot instance over p2p",
		RunE:  c.receive,
	}

	c.cobraCommand.SetUsageTemplate(usageTemplate)
	configuration.SetFlags(c.cobraCommand)

	return c.cobraCommand
}

func (c *Cmd) receive(cmd *cobra.Command, args []string) error {
	var (
		ctx = cmd.Context()
		log = zerolog.Ctx(ctx)

		p2pConfig = c.config.NATTraversal.P2P
		dsConfig  = c.config.Discovery
		baConfig  = c.config.BasicAuth
	)

	output.InvocationInfo(ctx, cmd, args)

	err := c.configureWebRTC()
	if err != nil {
		return err
	}

	var (
		signaller signallers.ClientSignaller
		transport *client.Transport
		bat       string
	)
	if webRTCSignallingDir := p2pConfig.DiscoveryDir; webRTCSignallingDir != "" {
		transport, err = client.NewTransport(c.webrtcConfig)
		if err != nil {
			return fmt.Errorf("failed to create transport: %w", err)
		}

		foundPair := false
		offerFilePath := filepath.Join(webRTCSignallingDir, "offer")
		answerFilePath := filepath.Join(webRTCSignallingDir, "answer")
		_, err := os.Stat(offerFilePath)
		if err == nil {
			_, err = os.Stat(answerFilePath)
			if err == nil {
				foundPair = true
			}
		}
		if !foundPair {
			dirContents, err := oneshotos.ReadDirSorted(webRTCSignallingDir, true)
			if err != nil {
				log.Error().Err(err).
					Msg("failed to read dir")

				return fmt.Errorf("failed to read dir: %w", err)
			}
			latestDir := dirContents[len(dirContents)-1].Name()

			ofp := filepath.Join(webRTCSignallingDir, latestDir, "offer")
			afp := filepath.Join(webRTCSignallingDir, latestDir, "answer")
			_, err = os.Stat(ofp)
			if err == nil {
				_, err = os.Stat(afp)
				if err == nil {
					offerFilePath = ofp
					answerFilePath = afp
					foundPair = true
				}
			}
		}
		if !foundPair {
			log.Error().
				Msg("no offer/answer pair found")

			return fmt.Errorf("no offer/answer pair found")
		}

		signaller, bat, err = signallers.NewFileClientSignaller(offerFilePath, answerFilePath)
	} else {
		corr, err := discovery.NegotiateOfferRequest(ctx, dsConfig.Addr, baConfig.Username, baConfig.Password, http.DefaultClient)
		if err != nil {
			return fmt.Errorf("failed to negotiate offer request: %w", err)
		}
		transport, err = client.NewTransport(corr.RTCConfiguration)
		if err != nil {
			return fmt.Errorf("failed to create transport: %w", err)
		}
		signaller, bat, err = signallers.NewServerClientSignaller(dsConfig.Addr, corr.SessionID, corr.RTCSessionDescription, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to create signaller: %w", err)
	}

	go func() {
		if err := signaller.Start(ctx, transport); err != nil {
			log.Printf("signaller error: %v", err)
		}
	}()
	defer signaller.Shutdown()

	log.Debug().Msg("waiting for connection to oneshot server to be established")

	if err = transport.WaitForConnectionEstablished(ctx); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Printf("... connection not established: %v", err)
			return nil
		}
	}

	log.Debug().Msg("connection to oneshot server established")

	preferredAddress, preferredPort := oneshotnet.PreferNonPrivateIP(transport.PeerAddresses())
	host := "http://localhost:8080"
	if preferredAddress != "" {
		host = net.JoinHostPort(preferredAddress, preferredPort)
	}

	req, err := http.NewRequest(http.MethodGet, "http://"+host, nil)
	if err != nil {
		return err
	}
	req.Close = true
	if bat != "" {
		req.Header.Set("X-HTTPOverWebRTC-Authorization", bat)
	}
	if preferredAddress != "" {
		req.RemoteAddr = host
	}

	events.Raise(ctx, output.NewHTTPRequest(req, nil))

	httpClient := http.Client{
		Transport: transport,
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to receive file: %s", resp.Status)
	}

	log.Debug().
		Int("status", resp.StatusCode).
		Interface("headers", resp.Header).
		Msg("received response from oneshot server")

	cl := int64(0)
	clString := resp.Header.Get("Content-Length")
	if clString == "" {
		cl, err = strconv.ParseInt(clString, 10, 64)
		if err == nil {
			cl = 0
		}
	}

	var location string
	if 0 < len(args) {
		location = args[0]
	}
	c.fileTransferConfig, err = file.NewWriteTransferConfig(ctx, location)
	if err != nil {
		log.Error().Err(err).
			Msg("failed to create file transfer config")

		return fmt.Errorf("failed to create file transfer config: %w", err)
	}

	wts, err := c.fileTransferConfig.NewWriteTransferSession(ctx, "", "")
	if err != nil {
		log.Error().Err(err).
			Msg("failed to create write transfer session")

		return fmt.Errorf("failed to create write transfer session: %w", err)
	}
	defer wts.Close()

	cancelProgDisp := output.DisplayProgress(
		ctx,
		&wts.Progress,
		125*time.Millisecond,
		req.RemoteAddr,
		cl,
	)
	defer cancelProgDisp()

	body, buf := output.NewBufferedReader(ctx, resp.Body)
	fileReport := events.File{
		Size:              cl,
		TransferStartTime: time.Now(),
	}

	n, err := io.Copy(wts, body)
	if err != nil {
		log.Error().Err(err).
			Msg("failed to copy response body to file")

		return fmt.Errorf("failed to copy response body to file after %d bytes: %w", n, err)
	}
	fileReport.TransferEndTime = time.Now()
	if buf != nil {
		fileReport.TransferSize = int64(buf.Len())
		fileReport.Content = buf.Bytes()
	}

	events.Raise(ctx, &fileReport)
	events.Success(ctx)
	events.Stop(ctx)

	return err
}

func (c *Cmd) configureWebRTC() error {
	conf := c.config.NATTraversal.P2P
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
	c.webrtcConfig = wc

	return nil
}
