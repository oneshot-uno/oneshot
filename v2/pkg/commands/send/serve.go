package send

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/forestnode-io/oneshot/v2/pkg/events"
	"github.com/forestnode-io/oneshot/v2/pkg/output"
)

func (c *Cmd) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var (
		ctx    = c.Cobra().Context()
		cmd    = c.cobraCommand
		config = c.config.Subcommands.Send
		header = http.Header(config.Header.Inflate())

		doneReadingBody = make(chan struct{})
	)

	events.Raise(ctx, output.NewHTTPRequest(r, nil))

	go func() {
		// Read body into the void since this will trigger a
		// a buffer on the body which can then be included in the
		// json report
		defer close(doneReadingBody)
		defer r.Body.Close()
		_, _ = io.Copy(io.Discard, r.Body)
	}()

	rts, err := c.rtc.NewReaderTransferSession(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		events.Raise(ctx, events.ClientDisconnected{Err: err})
		return
	}
	defer rts.Close()
	size, err := rts.Size()
	if err == nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	}

	for key := range header {
		w.Header().Set(key, header.Get(key))
	}
	w.WriteHeader(config.StatusCode)

	cancelProgDisp := output.DisplayProgress(
		cmd.Context(),
		&rts.Progress,
		125*time.Millisecond,
		r.RemoteAddr,
		0,
	)
	defer cancelProgDisp()

	// Start writing the file data to the client while timing how long it takes
	bw, getBufBytes := output.NewBufferedWriter(ctx, w)
	fileReport := events.File{
		Size:              int64(size),
		TransferStartTime: time.Now(),
	}

	n, err := io.Copy(bw, rts)
	fileReport.TransferSize = n
	fileReport.TransferEndTime = time.Now()
	if err != nil {
		events.Raise(ctx, &fileReport)
		events.Raise(ctx, events.ClientDisconnected{Err: err})
		return
	}

	fileReport.Content = getBufBytes
	events.Raise(ctx, &fileReport)

	events.Success(ctx)
	<-doneReadingBody
}
