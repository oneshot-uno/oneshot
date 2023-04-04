package receive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/pion/webrtc/v3"
	"github.com/raphaelreyna/oneshot/v2/pkg/commands/p2p/client/discovery"
	"github.com/raphaelreyna/oneshot/v2/pkg/events"
	"github.com/raphaelreyna/oneshot/v2/pkg/file"
	oneshotnet "github.com/raphaelreyna/oneshot/v2/pkg/net"
	oneshotwebrtc "github.com/raphaelreyna/oneshot/v2/pkg/net/webrtc"
	"github.com/raphaelreyna/oneshot/v2/pkg/net/webrtc/client"
	"github.com/raphaelreyna/oneshot/v2/pkg/net/webrtc/sdp/signallers"
	"github.com/raphaelreyna/oneshot/v2/pkg/output"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

func New() *Cmd {
	return &Cmd{}
}

type Cmd struct {
	cobraCommand       *cobra.Command
	fileTransferConfig *file.WriteTransferConfig
	webrtcConfig       *webrtc.Configuration
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

	flags := c.cobraCommand.Flags()
	flags.StringP("offer-file", "O", "", "Path to file containing the SDP offer.")
	flags.StringP("answer-file", "A", "", "Path to file which the SDP answer should be written to.")

	return c.cobraCommand
}

func (c *Cmd) receive(cmd *cobra.Command, args []string) error {
	var (
		ctx = cmd.Context()
		log = zerolog.Ctx(ctx)

		flags                  = cmd.Flags()
		offerFilePath, _       = flags.GetString("offer-file")
		answerFilePath, _      = flags.GetString("answer-file")
		webRTCSignallingDir, _ = flags.GetString("p2p-discovery-dir")
		webRTCSignallingURL, _ = flags.GetString("discovery-server-url")

		username, _ = flags.GetString("username")
		password, _ = flags.GetString("password")
	)

	output.InvocationInfo(ctx, cmd, args)

	err := c.configureWebRTC(flags)
	if err != nil {
		return err
	}

	var (
		signaller signallers.ClientSignaller
		transport *client.Transport
		bat       string
	)
	if webRTCSignallingDir != "" {
		transport, err = client.NewTransport(c.webrtcConfig)
		if err != nil {
			return fmt.Errorf("failed to create transport: %w", err)
		}
		signaller, bat, err = signallers.NewFileClientSignaller(offerFilePath, answerFilePath)
	} else {
		corr, err := discovery.NegotiateOfferRequest(ctx, webRTCSignallingURL, username, password, http.DefaultClient)
		if err != nil {
			return fmt.Errorf("failed to negotiate offer request: %w", err)
		}
		transport, err = client.NewTransport(corr.RTCConfiguration)
		if err != nil {
			return fmt.Errorf("failed to create transport: %w", err)
		}
		signaller, bat, err = signallers.NewServerClientSignaller(webRTCSignallingURL, corr.SessionID, corr.RTCSessionDescription, nil)
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

	events.Raise(ctx, output.NewHTTPRequest(req))

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

func (c *Cmd) configureWebRTC(flags *pflag.FlagSet) error {
	path, _ := flags.GetString("webrtc-config-file")
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("unable to read webrtc config file: %w", err)
	}

	config := oneshotwebrtc.Configuration{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("unable to parse webrtc config file: %w", err)
	}

	c.webrtcConfig, err = config.WebRTCConfiguration()
	if err != nil {
		return fmt.Errorf("unable to configure webrtc: %w", err)
	}

	return nil
}
