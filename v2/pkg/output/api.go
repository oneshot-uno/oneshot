package output

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/forestnode-io/oneshot/v2/pkg/events"
	"github.com/forestnode-io/oneshot/v2/pkg/log"
	"github.com/muesli/termenv"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

type UsageError struct {
	Err error
}

func UsageErrorF(format string, args ...interface{}) error {
	return UsageError{Err: fmt.Errorf(format, args...)}
}

func (n UsageError) Error() string {
	return n.Err.Error()
}

func WithOutput(ctx context.Context) (context.Context, error) {
	o := output{
		doneChan:            make(chan struct{}),
		disconnectedClients: make([]*ClientSession, 0),
		FormatOpts:          map[string]struct{}{},
	}

	if err := o.ttyCheck(); err != nil {
		return nil, err
	}

	return context.WithValue(ctx, key{}, &o), nil
}

func InvocationInfo(ctx context.Context, cmd *cobra.Command, args []string) {
	log := zerolog.Ctx(ctx)
	o := getOutput(ctx)
	o.setCommandInvocation(cmd, args)

	go func() {
		if err := getOutput(ctx).run(ctx); err != nil {
			log.Error().Err(err).
				Msg("error running output system")
		}
	}()
}

func SetEventsChan(ctx context.Context, ec chan events.Event) {
	getOutput(ctx).events = ec
}

func WriteListeningOnQR(ctx context.Context, addr string) {
	getOutput(ctx).writeListeningOnQRCode(addr)
}

func WriteListeningOn(ctx context.Context, addr string) {
	getOutput(ctx).writeListeningOn(addr)
}

func Quiet(ctx context.Context) {
	getOutput(ctx).quiet = true
}

func SetFormat(ctx context.Context, f string) {
	getOutput(ctx).Format = f
}

func SetFormatOpts(ctx context.Context, opts ...string) {
	o := getOutput(ctx)
	for _, opt := range opts {
		o.FormatOpts[opt] = struct{}{}
	}
}

func IncludeBody(ctx context.Context) {
	getOutput(ctx).includeBody = true
}

func GetFormatAndOpts(ctx context.Context) (string, map[string]struct{}) {
	o := getOutput(ctx)
	return o.Format, o.FormatOpts
}

func NoColor(ctx context.Context) {
	o := getOutput(ctx)
	o.stdoutFailColor = nil
	o.stderrFailColor = nil
}

func RestoreCursor(ctx context.Context) {
	o := getOutput(ctx)
	if o.dynamicOutput == nil {
		return
	}
	do := o.dynamicOutput
	if do.restoredCursor {
		return
	}
	do.ShowCursor()
}

func ReceivingToStdout(ctx context.Context) {
	getOutput(ctx).receivingToStdout = true
}

func WriteAllReceivedInputToStdout(ctx context.Context) {
	getOutput(ctx).writeAllReceivedInputToStdout = true
}

func Wait(ctx context.Context) {
	o := getOutput(ctx)
	if o.gotInvocationInfo {
		<-o.doneChan
	}
}

func GetBufferedWriteCloser(ctx context.Context) io.WriteCloser {
	o := getOutput(ctx)
	if !o.receivingToStdout || o.Format == "json" || !o.writeAllReceivedInputToStdout {
		return &writer{}
	}
	return &writer{os.Stdout}
}

func DisplayProgress(ctx context.Context, prog *atomic.Int64, period time.Duration, host string, total int64) func() {
	o := getOutput(ctx)
	if o.receivingToStdout || o.quiet || o.Format == "json" {
		return func() {}
	}

	var (
		done chan struct{}

		start  = time.Now()
		prefix = fmt.Sprintf("%s\t%s", start.Format(progDisplayTimeFormat), host)
	)

	if o.dynamicOutput != nil {
		o.displayProgresssPeriod = period
		displayDynamicProgress(o, prefix, start, prog, total)

		done = make(chan struct{})
		ticker := time.NewTicker(period)

		go func() {
			for {
				select {
				case <-done:
					ticker.Stop()
					return
				case <-ticker.C:
					displayDynamicProgress(o, prefix, start, prog, total)
				}
			}
		}()
	}

	return func() {
		if done != nil {
			done <- struct{}{}
			close(done)
			done = nil
		}

		if events.Succeeded(ctx) {
			displayProgressSuccessFlush(o, prefix, start, prog.Load())
		} else {
			displayProgressFailFlush(o, prefix, start, prog.Load(), total)
		}
	}
}

func NewBufferedWriter(ctx context.Context, w io.Writer) (io.Writer, func() []byte) {
	o := getOutput(ctx)

	if _, ok := o.FormatOpts["exclude-file-contents"]; ok {
		return w, nil
	}

	_, includeFileContents := o.FormatOpts["include-file-contents"]

	// if the command name is 'reverse-proxy' or the format
	// is json for any other command, buffer the output
	if o.Format == "json" || o.cmdName == "reverse-proxy" || includeFileContents {
		buf := bytes.NewBuffer(nil)
		tw := teeWriter{
			w:    w,
			copy: buf,
		}

		return tw, buf.Bytes
	}

	return w, nil
}

func NewBufferedReader(ctx context.Context, r io.Reader) (io.Reader, *bytes.Buffer) {
	o := getOutput(ctx)

	if _, ok := o.FormatOpts["exclude-file-contents"]; ok {
		return r, nil
	}

	_, includeFileContents := o.FormatOpts["include-file-contents"]

	// if the command name is 'reverse-proxy' or the format
	// is json for any other command, buffer the output
	if o.Format == "json" || o.cmdName == "reverse-proxy" || includeFileContents {
		buf := bytes.NewBuffer(nil)
		tr := io.TeeReader(r, buf)

		return tr, buf
	}

	return r, nil
}

type teeWriter struct {
	w, copy io.Writer
}

func (t teeWriter) Write(p []byte) (n int, err error) {
	n, err = t.w.Write(p)
	if n > 0 {
		n, err := t.copy.Write(p[:n])
		if err != nil {
			return n, err
		}
	}
	return
}

func (t teeWriter) Header() http.Header {
	if h, ok := t.w.(http.ResponseWriter); ok {
		return h.Header()
	}
	return nil
}

func (t teeWriter) WriteHeader(code int) {
	if h, ok := t.w.(http.ResponseWriter); ok {
		h.WriteHeader(code)
	}
}

type writer struct {
	w io.Writer
}

func (w *writer) Write(p []byte) (int, error) {
	if w.w == nil {
		return len(p), nil
	}
	return w.w.Write(p)
}

func (*writer) Close() error {
	return nil
}

type tabbedDynamicOutput struct {
	tw             *tabwriter.Writer
	te             *termenv.Output
	restoredCursor bool
}

func newTabbedDynamicOutput(te *termenv.Output) *tabbedDynamicOutput {
	return &tabbedDynamicOutput{
		tw: tabwriter.NewWriter(te, 12, 2, 2, ' ', 0),
		te: termenv.NewOutput(te),
	}
}

func (o *tabbedDynamicOutput) resetLine() {
	log := log.Logger()

	_, err := o.te.WriteString("\r")
	if err != nil {
		log.Error().Err(err).
			Msg("error writing carriage-return character")
	}
	o.te.ClearLineRight()
}

func (o *tabbedDynamicOutput) flush() error {
	return o.tw.Flush()
}

func (o *tabbedDynamicOutput) Write(p []byte) (int, error) {
	return o.tw.Write(p)
}

func (o *tabbedDynamicOutput) ShowCursor() {
	o.te.ShowCursor()
	o.restoredCursor = true
}

func (o *tabbedDynamicOutput) HideCursor() {
	o.te.HideCursor()
}

func (o *tabbedDynamicOutput) EnvNoColor() bool {
	return o.te.EnvNoColor()
}

func (o *tabbedDynamicOutput) Color(s string) termenv.Color {
	return o.te.Color(s)
}

func (o *tabbedDynamicOutput) String(s string) termenv.Style {
	return o.te.String(s)
}
