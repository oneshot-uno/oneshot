package client

import (
	"github.com/raphaelreyna/oneshot/v2/pkg/commands/p2p/client/receive"
	"github.com/raphaelreyna/oneshot/v2/pkg/commands/p2p/client/send"
	"github.com/raphaelreyna/oneshot/v2/pkg/configuration"
	"github.com/spf13/cobra"
)

func New(config *configuration.Root) *Cmd {
	return &Cmd{
		config: config,
	}
}

type Cmd struct {
	cobraCommand *cobra.Command
	config       *configuration.Root
}

func (c *Cmd) Cobra() *cobra.Command {
	if c.cobraCommand != nil {
		return c.cobraCommand
	}

	c.cobraCommand = &cobra.Command{
		Use:   "client",
		Short: "WebRTC client commands",
		Long:  "WebRTC client commands",
	}

	c.cobraCommand.AddCommand(subCommands(c.config)...)

	return c.cobraCommand
}

func subCommands(config *configuration.Root) []*cobra.Command {
	return []*cobra.Command{
		send.New(config).Cobra(),
		receive.New(config).Cobra(),
	}
}
