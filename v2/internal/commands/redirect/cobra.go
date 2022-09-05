package redirect

import (
	"errors"
	"net/http"

	"github.com/raphaelreyna/oneshot/v2/internal/api"
	"github.com/raphaelreyna/oneshot/v2/internal/commands/shared"
	"github.com/raphaelreyna/oneshot/v2/internal/out"
	"github.com/raphaelreyna/oneshot/v2/internal/server"
	"github.com/spf13/cobra"
)

func New() *Cmd {
	return &Cmd{
		header: make(http.Header),
	}
}

type Cmd struct {
	cobraCommand *cobra.Command
	header       http.Header
	statusCode   int
	url          string
}

func (c *Cmd) Cobra() *cobra.Command {
	c.cobraCommand = &cobra.Command{
		Use:  "redirect url",
		RunE: c.runE,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("redirect url required")
			}
			if 1 < len(args) {
				return errors.New("too many arguments, only 1 url may be used")
			}
			return nil
		},
	}

	flags := c.cobraCommand.LocalFlags()
	flags.IntP("status-code", "s", http.StatusTemporaryRedirect, "HTTP status code")

	return c.cobraCommand
}

func (c *Cmd) runE(cmd *cobra.Command, args []string) error {
	var (
		ctx = cmd.Context()

		flags                = c.cobraCommand.Flags()
		statCode, statCodeOk = flags.GetInt("status-code")
		headerSlice, _       = flags.GetStringSlice("header")
	)

	if statCodeOk != nil {
		statCode = http.StatusTemporaryRedirect
	}

	c.url = args[0]
	c.statusCode = statCode
	c.header = shared.HeaderFromStringSlice(headerSlice)

	srvr := server.NewServer(c.ServeHTTP, c.ServeExpiredHTTP)
	server.SetServer(ctx, srvr)
	return nil
}

func (c *Cmd) ServeHTTP(actx api.Context, w http.ResponseWriter, r *http.Request) {
	actx.Raise(out.NewHTTPRequest(r))

	var header = c.header
	for key := range header {
		w.Header().Set(key, header.Get(key))
	}

	http.Redirect(w, r, c.url, c.statusCode)

	actx.Success()
}

func (s *Cmd) ServeExpiredHTTP(_ api.Context, w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("expired hello from server"))
}
