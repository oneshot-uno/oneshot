package output

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/forestnode-io/oneshot/v2/pkg/events"
	"github.com/forestnode-io/oneshot/v2/pkg/net/webrtc/signallingserver/messages"
	"github.com/mdp/qrterminal/v3"
	"github.com/muesli/termenv"
	"github.com/rs/zerolog"
)

var NewHTTPRequest = events.NewHTTPRequest

type key struct{}

func getOutput(ctx context.Context) *output {
	o, _ := ctx.Value(key{}).(*output)
	if o == nil {
		panic("no output set")
	}
	return o
}

type output struct {
	events chan events.Event

	stderrTTY *termenv.Output

	dynamicOutput *tabbedDynamicOutput

	Format     string
	FormatOpts map[string]struct{}

	includeBody       bool
	receivingToStdout bool
	receivedBuf       *bytes.Buffer

	disconnectedClients  []*ClientSession
	currentClientSession *ClientSession

	quiet bool

	doneChan chan struct{}

	displayProgresssPeriod    time.Duration
	lastProgressDisplayAmount int64

	restoreConsole  []func() error
	stdoutFailColor termenv.Color
	stderrFailColor termenv.Color

	gotInvocationInfo bool

	cmdName string
}

func (o *output) run(ctx context.Context) error {
	log := zerolog.Ctx(ctx)

	log.Debug().
		Msg("output running in json mode")
	NewHTTPRequest = events.NewHTTPRequest_WithBody
	runJSON(ctx, o)

	log.Debug().
		Msg("output system shutting down")

	for _, f := range o.restoreConsole {
		if err := f(); err != nil {
			log.Error().Err(err).
				Msg("error from console restore func")
		}
	}

	close(o.doneChan)

	log.Debug().
		Msg("output system shut down")

	return nil
}

func (o *output) writeListeningOnQRCode(addr string) {
	if o.quiet || addr == "" {
		return
	}

	qrConf := qrterminal.Config{
		Level:      qrterminal.L,
		Writer:     os.Stderr,
		BlackChar:  qrterminal.BLACK,
		WhiteChar:  qrterminal.WHITE,
		QuietZone:  1,
		HalfBlocks: false,
	}

	fmt.Fprintln(os.Stderr, addr)
	qrterminal.GenerateWithConfig(addr, qrConf)
}

func (o *output) writeListeningOn(addr string) {
	if o.quiet || addr == "" {
		return
	}

	fmt.Fprintf(os.Stderr, "listening on %s\n", addr)
}

// ttyCheck checks if stdin, stdout, and stderr are ttys
// and records it in o.
func (o *output) ttyCheck() error {
	stat, err := os.Stderr.Stat()
	if err != nil {
		return err
	}
	stderrIsTTY := (stat.Mode() & os.ModeCharDevice) == os.ModeCharDevice

	// if we're running in a docker container, assume both stdout and stderr are ttys
	if _, err := os.Stat("/.dockerenv"); err == nil {
		stderrIsTTY = true
	}

	if os.Getenv("ONESHOT_TESTING_TTY_STDERR") != "" {
		stderrIsTTY = true
	}

	if stderrIsTTY {
		o.stderrTTY = termenv.NewOutput(os.Stderr)
		restoreStderr, err := termenv.EnableVirtualTerminalProcessing(o.stderrTTY)
		if err != nil {
			return err
		}
		if !o.stderrTTY.EnvNoColor() {
			o.stderrFailColor = o.stderrTTY.Color("#ff0000")
		}
		o.restoreConsole = append(o.restoreConsole, restoreStderr)
	}

	return nil
}

func (o *output) enableDynamicOutput() {
	if o.stderrTTY == nil {
		return
	}

	o.dynamicOutput = newTabbedDynamicOutput(o.stderrTTY)
	o.dynamicOutput.HideCursor()
	o.restoreConsole = append(o.restoreConsole, func() error {
		if o.dynamicOutput != nil {
			o.dynamicOutput.ShowCursor()
			o.dynamicOutput = nil
		}
		return nil
	})
}

type ClientSession struct {
	Request  *events.HTTPRequest  `json:",omitempty"`
	File     *events.File         `json:",omitempty"`
	Response *events.HTTPResponse `json:",omitempty"`
	Error    string               `json:",omitempty"`
}

func newClientSessionMessage(s *ClientSession) *messages.ClientSession {
	return &messages.ClientSession{
		Request:  messages.HTTPRequestFromEvent(s.Request),
		File:     messages.FileFromEvent(s.File),
		Response: messages.HTTPResponseFromEvent(s.Response),
		Error:    s.Error,
	}
}

type Report struct {
	Success  *ClientSession   `json:",omitempty"`
	Attempts []*ClientSession `json:",omitempty"`
}

func newReportMessage(report *Report) *messages.Report {
	r := messages.Report{
		Success:  newClientSessionMessage(report.Success),
		Attempts: make([]*messages.ClientSession, len(report.Attempts)),
	}

	for i, s := range report.Attempts {
		r.Attempts[i] = newClientSessionMessage(s)
	}

	return &r
}

func bytesPerSecond(bytes int64, dt time.Duration) float64 {
	const floatSecond = float64(time.Second)
	return float64(bytes) / float64(dt) * floatSecond
}
