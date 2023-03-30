package browserclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/pion/webrtc/v3"
	"github.com/pkg/browser"
	"github.com/raphaelreyna/oneshot/v2/pkg/commands/webrtc/signalling-server/template"
	"github.com/raphaelreyna/oneshot/v2/pkg/events"
	oneshotwebrtc "github.com/raphaelreyna/oneshot/v2/pkg/net/webrtc"
	"github.com/raphaelreyna/oneshot/v2/pkg/output"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

func New() *Cmd {
	return &Cmd{}
}

type Cmd struct {
	cobraCommand *cobra.Command
	webrtcConfig *webrtc.Configuration
}

func (c *Cmd) Cobra() *cobra.Command {
	if c.cobraCommand != nil {
		return c.cobraCommand
	}

	c.cobraCommand = &cobra.Command{
		Use:   "browser-client",
		Short: "Get the webrtc browser client",
		Long:  "Get the webrtc browser client",
		RunE:  c.run,
	}

	flags := c.cobraCommand.Flags()
	flags.Bool("open", false, "Open the client in the browser automatically")

	return c.cobraCommand
}

func (c *Cmd) run(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	output.InvocationInfo(ctx, cmd, args)
	defer func() {
		events.Succeeded(ctx)
		events.Stop(ctx)
	}()

	if err := c.configureWebRTC(cmd.Flags()); err != nil {
		return err
	}

	rtcConfigJSON, err := json.Marshal(c.webrtcConfig)
	if err != nil {
		return fmt.Errorf("unable to marshal webrtc config: %w", err)
	}

	tmpltCtx := template.Context{
		AutoConnect:   false,
		ClientJS:      template.ClientJS,
		RTCConfigJSON: string(rtcConfigJSON),
	}
	buf := bytes.NewBuffer(nil)
	err = template.WriteTo(buf, tmpltCtx)
	if err != nil {
		return fmt.Errorf("unable to write template: %w", err)
	}

	openBrowser, _ := cmd.Flags().GetBool("open")
	if openBrowser {
		if err := browser.OpenReader(buf); err != nil {
			log.Println("failed to open browser:", err)
		}
	} else {
		fmt.Print(buf.String())
	}

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
