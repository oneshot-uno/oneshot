package exec

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/forestnode-io/oneshot/v2/pkg/cgi"
	"github.com/forestnode-io/oneshot/v2/pkg/commands"
	"github.com/forestnode-io/oneshot/v2/pkg/commands/exec/configuration"
	rootconfig "github.com/forestnode-io/oneshot/v2/pkg/configuration"
	"github.com/forestnode-io/oneshot/v2/pkg/events"
	"github.com/forestnode-io/oneshot/v2/pkg/output"
	"github.com/spf13/cobra"
)

type Cmd struct {
	cobraCommand *cobra.Command
	handler      *cgi.Handler
	config       *rootconfig.Root
}

func New(config *rootconfig.Root) *Cmd {
	return &Cmd{
		config: config,
	}
}

func (c *Cmd) Cobra() *cobra.Command {
	if c.cobraCommand != nil {
		return c.cobraCommand
	}

	c.cobraCommand = &cobra.Command{
		Use:        "exec -- command",
		Aliases:    []string{"execute", "cgi"},
		SuggestFor: []string{"send"},
		Short:      "Execute a command for each request, passing in the body to stdin and returning the stdout to the client",
		Long: `Execute a command for each request, passing in the body to stdin and returning the stdout to the client.
Commands may be CGI complaint but do not have to be. CGI compliance can be enforced with the --enforce-cgi flag.`,
		RunE: c.setHandlerFunc,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return output.UsageErrorF("missing command")
			}

			return nil
		},
	}

	c.cobraCommand.SetUsageTemplate(usageTemplate)
	configuration.SetFlags(c.cobraCommand)

	return c.cobraCommand
}

func (c *Cmd) setHandlerFunc(cmd *cobra.Command, args []string) error {
	var (
		ctx    = cmd.Context()
		config = c.config.Subcommands.Exec
		header = config.Header
	)

	output.IncludeBody(ctx)

	handlerConf := cgi.HandlerConfig{
		Cmd:           args,
		WorkingDir:    config.Dir,
		InheritEnvs:   nil,
		BaseEnv:       config.Env,
		Header:        header.Inflate(),
		OutputHandler: cgi.DefaultOutputHandler,
		Stderr:        cmd.ErrOrStderr(),
	}

	switch {
	case config.ReplaceHeaders:
		handlerConf.OutputHandler = cgi.OutputHandlerReplacer
	case config.EnforceCGI:
		handlerConf.OutputHandler = cgi.DefaultOutputHandler
	default:
		handlerConf.OutputHandler = cgi.EZOutputHandler
	}
	if config.StdErr != "" {
		var err error
		handlerConf.Stderr, err = os.Open(config.StdErr)
		if err != nil {
			return fmt.Errorf("failed to open stderr file: %w", err)
		}
		commands.MarkForClose(ctx, handlerConf.Stderr.(io.WriteCloser))
	} else {
		handlerConf.Stderr = cmd.ErrOrStderr()
	}

	handler, err := cgi.NewHandler(handlerConf)
	if err != nil {
		return fmt.Errorf("failed to create CGI handler: %w", err)
	}

	c.handler = handler
	commands.SetHTTPHandlerFunc(ctx, c.ServeHTTP)
	return nil
}

func (c *Cmd) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := c.cobraCommand.Context()
	events.Raise(ctx, output.NewHTTPRequest(r, nil))

	bw, getBufBytes := output.NewBufferedWriter(ctx, w)
	brw := output.ResponseWriter{
		W:         w,
		BufferedW: bw,
	}
	fileReport := events.File{
		TransferStartTime: time.Now(),
	}

	c.handler.ServeHTTP(&brw, r)

	fileReport.TransferEndTime = time.Now()
	fileReport.Content = getBufBytes
	events.Raise(ctx, &fileReport)

	events.Success(ctx)
}
