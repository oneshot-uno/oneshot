package redirect

import (
	"io"
	"net/http"

	"github.com/forestnode-io/oneshot/v2/pkg/commands"
	"github.com/forestnode-io/oneshot/v2/pkg/commands/redirect/configuration"
	rootconfig "github.com/forestnode-io/oneshot/v2/pkg/configuration"
	"github.com/forestnode-io/oneshot/v2/pkg/events"
	"github.com/forestnode-io/oneshot/v2/pkg/output"
	"github.com/spf13/cobra"
)

func New(config *rootconfig.Root) *Cmd {
	return &Cmd{
		config: config,
	}
}

type Cmd struct {
	cobraCommand *cobra.Command
	config       *rootconfig.Root
	url          string
}

func (c *Cmd) Cobra() *cobra.Command {
	if c.cobraCommand != nil {
		return c.cobraCommand
	}

	c.cobraCommand = &cobra.Command{
		Use:   "redirect url",
		Short: "Redirect all requests to the specified url",
		RunE:  c.setHandlerFunc,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return output.UsageErrorF("redirect url required")
			}
			if 1 < len(args) {
				return output.UsageErrorF("too many arguments, only 1 url may be used")
			}
			return nil
		},
	}

	c.cobraCommand.SetUsageTemplate(usageTemplate)
	configuration.SetFlags(c.cobraCommand)

	return c.cobraCommand
}

func (c *Cmd) setHandlerFunc(cmd *cobra.Command, args []string) error {
	var ctx = cmd.Context()

	output.IncludeBody(ctx)

	c.url = args[0]

	commands.SetHTTPHandlerFunc(ctx, c.ServeHTTP)
	return nil
}

func (c *Cmd) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var (
		ctx    = c.cobraCommand.Context()
		config = c.config.Subcommands.Redirect
	)

	doneReadingBody := make(chan struct{})
	events.Raise(ctx, output.NewHTTPRequest(r, nil))

	var header = http.Header(config.Header.Inflate())
	for key := range header {
		w.Header().Set(key, header.Get(key))
	}

	go func() {
		defer close(doneReadingBody)
		defer r.Body.Close()
		_, _ = io.Copy(io.Discard, r.Body)
	}()

	http.Redirect(w, r, c.url, config.StatusCode)

	events.Success(ctx)
	<-doneReadingBody
}
