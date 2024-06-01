package receive

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/forestnode-io/oneshot/v2/pkg/events"
	oneshothttp "github.com/forestnode-io/oneshot/v2/pkg/net/http"
	"github.com/forestnode-io/oneshot/v2/pkg/output"
	"github.com/rs/zerolog"
)

func (c *Cmd) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var (
		ctx = c.cobraCommand.Context()
		log = zerolog.Ctx(ctx)
	)

	if r.Method == "GET" {
		log.Debug().
			Msg("serving receive browser client")

		c._handleGET(w, r)
		return
	}

	var (
		config           = c.config.Subcommands.Receive
		rb               *requestBody
		readerMiddleware func(io.Reader) io.Reader
		err              error
	)

	if config.DecodeBase64 {
		readerMiddleware = func(r io.Reader) io.Reader {
			return base64.NewDecoder(base64.StdEncoding, r)
		}
	}

	events.Raise(ctx, output.NewHTTPRequest(r, readerMiddleware))

	rct := r.Header.Get("Content-Type")
	log.Debug().
		Str("content-type", rct).
		Msg("raise new request event")

	// Switch on the type of upload to obtain the appropriate src io.Reader to read data from.
	// Uploads may happen by uploading a file, uploading text from an HTML text box, or straight from the request body
	switch {
	case strings.Contains(rct, "multipart/form-data"): // User uploaded a file
		rb, err = c.readCloserFromMultipartFormData(r)
	case r.Header.Get("Content-Length") != "0": // this usually means there's a non-empty body, lets grab it
		rb, err = c.readCloserFromRawBody(r)
	case strings.Contains(rct, "application/x-www-form-urlencoded"): // User uploaded text from HTML text box
		rb, err = c.readCloserFromApplicationWWWForm(r)
	default: // Could not determine how file upload was initiated, grabbing the request body
		rb, err = c.readCloserFromRawBody(r)
	}
	defer r.Body.Close()
	if err != nil {
		log.Error().Err(err).
			Msg("error determining upload type")

		http.Error(w, err.Error(), err.(*httpError).stat)
		events.Raise(ctx, events.ClientDisconnected{Err: err})
		return
	}

	src := rb.r
	decodeB64 := config.DecodeBase64
	if decodeB64 && 0 < rb.size {
		src = io.NopCloser(base64.NewDecoder(base64.StdEncoding, src))
	}

	fileSize := int(rb.size)
	if fileSize != 0 {
		// if decoding base64
		if decodeB64 {
			fileSize = base64.StdEncoding.DecodedLen(fileSize)
		}
	}

	wts, err := c.fileTransferConfig.NewWriteTransferSession(ctx, rb.name, rb.mime)
	if err != nil {
		log.Error().Err(err).
			Msg("error creating write transfer session")

		http.Error(w, err.Error(), http.StatusInternalServerError)
		events.Raise(ctx, events.ClientDisconnected{Err: err})
		return
	}
	defer wts.Close()

	log.Debug().Msg("created write transfer session")

	cancelProgDisp := output.DisplayProgress(
		ctx,
		&wts.Progress,
		125*time.Millisecond,
		r.RemoteAddr,
		int64(fileSize),
	)
	defer cancelProgDisp()

	log.Debug().Msg("started progress display")

	file, getBufBytes := output.NewBufferedWriter(ctx, wts)
	fileReport := events.File{
		MIME:              rb.mime,
		Size:              int64(fileSize),
		Name:              rb.name,
		TransferStartTime: time.Now(),
	}

	log.Debug().Msg("starting file copy")

	fileReport.TransferSize, err = io.Copy(file, src)
	fileReport.TransferEndTime = time.Now()

	log.Debug().Msg("finished file copy")

	if err != nil {
		log.Error().Err(err).
			Msg("error copying file from request")

		events.Raise(ctx, &fileReport)
		events.Raise(ctx, events.ClientDisconnected{
			Err: err,
		})
		return
	}

	w.WriteHeader(config.StatusCode)

	fileReport.Path = wts.Path()
	fileReport.Content = getBufBytes
	events.Raise(ctx, &fileReport)

	events.Success(ctx)
}

func (c *Cmd) _handleGET(w http.ResponseWriter, r *http.Request) {
	log := zerolog.Ctx(r.Context())

	w.(oneshothttp.ResponseWriter).IgnoreOutcome()
	defer r.Body.Close()

	withJS := true
	ua := r.Header.Get("User-Agent")
	if strings.Contains(ua, "curl") || strings.Contains(ua, "wget") {
		withJS = false
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := c.writeTemplate(w, withJS); err != nil {
		log.Error().Err(err).
			Msg("failed to write template")

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
