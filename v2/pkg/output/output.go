package output

import (
	"bytes"
	"context"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/mdp/qrterminal/v3"
	"github.com/muesli/termenv"
	"github.com/raphaelreyna/oneshot/v2/pkg/events"
	oneshotnet "github.com/raphaelreyna/oneshot/v2/pkg/net"
	oneshotfmt "github.com/raphaelreyna/oneshot/v2/pkg/output/fmt"
)

type key struct{}

func getOutput(ctx context.Context) *output {
	o, _ := ctx.Value(key{}).(*output)
	if o == nil {
		panic("no output set")
	}
	return o
}

type output struct {
	events       chan events.Event
	Stdout       *termenv.Output
	Stderr       *termenv.Output
	tabbedStdout *tabwriter.Writer
	tabbedStderr *tabwriter.Writer
	Format       string
	FormatOpts   []string

	skipSummary     bool
	servingToStdout bool
	receivedBuf     *bytes.Buffer

	cls                  []*clientSession
	currentClientSession *clientSession

	quiet bool

	doneChan chan struct{}

	stdoutIsTTY bool
	stderrIsTTY bool

	displayProgresssPeriod    time.Duration
	lastProgressDisplayAmount int64

	restoreConsole  func()
	stdoutFailColor termenv.Color
	stderrFailColor termenv.Color
}

func (o *output) run(ctx context.Context) error {
	if o.quiet {
		runQuiet(ctx, o)
	} else {
		if !o.servingToStdout && o.stderrIsTTY {
			o.Stderr.HideCursor()
		}

		switch o.Format {
		case "":
			runHuman(ctx, o)
		case "json":
			NewHTTPRequest = events.NewHTTPRequest_WithBody
			runJSON(ctx, o)
		}

		if o.servingToStdout && o.Format != "json" {
			fmt.Fprint(o.Stdout, "\n")
		} else {
			if o.stderrIsTTY {
				o.Stderr.ShowCursor()
			}
		}
	}
	o.restoreConsole()
	o.doneChan <- struct{}{}
	return nil
}

func (o *output) writeListeningOnQRCode(scheme, host, port string) {
	qrConf := qrterminal.Config{
		Level:      qrterminal.L,
		Writer:     o.Stderr,
		BlackChar:  qrterminal.BLACK,
		WhiteChar:  qrterminal.WHITE,
		QuietZone:  1,
		HalfBlocks: false,
	}
	if o.Format == "json" || o.skipSummary {
		return
	}

	if host == "" {
		addrs, err := oneshotnet.HostAddresses()
		if err != nil {
			addr := fmt.Sprintf("%s://localhost%s", scheme, port)
			fmt.Fprintf(o.Stderr, "%s:\n", addr)
			qrterminal.GenerateWithConfig(addr, qrConf)
			return
		}

		fmt.Fprintln(o.Stderr, "listening on: ")
		for _, addr := range addrs {
			addr = fmt.Sprintf("%s://%s", scheme, oneshotfmt.Address(addr, port))
			fmt.Fprintf(o.Stderr, "%s:\n", addr)
			qrterminal.GenerateWithConfig(addr, qrConf)
		}
		return
	}

	addr := fmt.Sprintf("%s://%s", scheme, oneshotfmt.Address(host, port))
	fmt.Fprintf(o.Stderr, "%s:\n", addr)
	qrterminal.GenerateWithConfig(addr, qrConf)
}

type clientSession struct {
	Request *events.HTTPRequest `json:",omitempty"`
	File    *events.File        `json:",omitempty"`
}

type report struct {
	Success  *clientSession
	Attempts []*clientSession
}

func bytesPerSecond(bytes int64, dt time.Duration) float64 {
	const floatSecond = float64(time.Second)
	return float64(bytes) / float64(dt) * floatSecond
}