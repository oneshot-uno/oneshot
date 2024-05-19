package output

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/forestnode-io/oneshot/v2/pkg/events"
	"github.com/forestnode-io/oneshot/v2/pkg/net/webrtc/signallingserver"
	"github.com/rs/zerolog"
)

func runJSON(ctx context.Context, o *output) {
	for event := range o.events {
		_json_handleEvent(o, event)
	}
	_json_handleContextDone(ctx, o)
}

func _json_handleEvent(o *output, e events.Event) {
	humanOutput := o.Format == ""

	_, includeFileContent := o.FormatOpts["include-file-contents"]
	// if the user want to receive to stdout then the received content won't be saved to disk
	// so we include it in the json report which is going to stdout
	if _, exclude := o.FormatOpts["exclude-file-contents"]; exclude {
		includeFileContent = false
	}

	switch event := e.(type) {
	case events.ClientDisconnected:
		// if an error occurred, then set the error message
		if err := event.Err; err != nil {
			o.currentClientSession.Error = err.Error()
		}

		// add the client to the list of disconnected clients and reset the current client
		o.disconnectedClients = append(o.disconnectedClients, o.currentClientSession)
		o.currentClientSession = nil
	case *events.HTTPRequest:
		// a new client connected, so create a new client session
		// and store it as the current client session
		o.currentClientSession = &ClientSession{
			Request: event,
		}
	case *events.File:
		// if the command is reverse-proxy, then the file is the response
		// and so we store it in the current client session
		if o.cmdName == "reverse-proxy" {
			if o.currentClientSession != nil {
				if o.currentClientSession.Response == nil {
					o.currentClientSession.Response = &events.HTTPResponse{}
				}

				if bf, ok := event.Content.(func() []byte); ok {
					bodyBytes := bf()
					o.currentClientSession.Response.Body = bodyBytes
					if humanOutput && !o.quiet {
						os.Stdout.Write(bodyBytes)
					}
				}
			}

			return
		}

		// otherwise, if we're in the middle of a client session
		if o.currentClientSession != nil {
			// then store the file in the current client session
			o.currentClientSession.File = event
			// if the content is a thunk and not bytes
			if bf, ok := o.currentClientSession.File.Content.(func() []byte); ok && bf != nil {
				// and the user wants to include the file content in the report
				if includeFileContent {
					// then store the content in the current client session
					o.currentClientSession.File.Content = bf()
					// and set the transfer size to the length of the content
					if o.currentClientSession.File.TransferSize == 0 {
						o.currentClientSession.File.TransferSize = int64(len(o.currentClientSession.File.Content.([]byte)))
					}
				} else {
					// otherwise, dump the contents
					_ = bf()
					o.currentClientSession.File.Content = nil
				}
			}
		}
	case *events.HTTPResponse:
		// if we're in the middle of client session
		if o.currentClientSession != nil {
			// and the client session already reported a response
			if o.currentClientSession.Response != nil {
				// and gave us a body
				if o.currentClientSession.Response.Body != nil {
					// then copy the body over to the event body if we have the body as bytes
					if body, ok := o.currentClientSession.Response.Body.([]byte); ok {
						event.Body = body
					}
				}
			}
			// then store the response in the current client session
			o.currentClientSession.Response = event
		}
	case events.HTTPRequestBody:
		if humanOutput {
			body, err := event()
			if err != nil {
				panic(err)
			}
			o.currentClientSession.Request.Body = body
			if !o.quiet {
				fmt.Fprintln(os.Stdout, string(body))
			}
		}
	}
}

func _json_handleContextDone(ctx context.Context, o *output) {
	log := zerolog.Ctx(ctx)

	if err := events.GetCancellationError(ctx); err != nil {
		log.Error().
			Msg("connection cancelled event")
	}

	if o.receivingToStdout && !o.writeAllReceivedInputToStdout && !(o.Format == "json") {
		if o.currentClientSession != nil {
			if o.currentClientSession.Request != nil {
				if err := o.currentClientSession.Request.ReadBody(); err != nil {
					log.Error().Err(err).
						Msg("error reading request body buffer")
				}

				bodyBytes, ok := o.currentClientSession.Request.Body.([]byte)
				if ok {
					os.Stdout.Write(bodyBytes)
				}
			}
		}
	}

	// if we want to include the body
	if o.includeBody {
		// and we have a client session
		if o.currentClientSession != nil {
			// and the client session has already reported a request
			if o.currentClientSession.Request != nil {
				// then read in the body since it wasn't written to disk
				if err := o.currentClientSession.Request.ReadBody(); err != nil {
					log.Error().Err(err).
						Msg("error reading request body buffer")
				}
			}
		}
	} else if o.currentClientSession != nil {
		if o.currentClientSession.Request != nil {
			// otherwise, there's no point in showing the content again in stdout
			o.currentClientSession.Request.Body = nil
		}
	}
	if o.currentClientSession != nil {
		if file := o.currentClientSession.File; file != nil {
			if bf, ok := file.Content.(func() []byte); ok {
				if bf != nil {
					buf := bf()
					file.Content = buf
					file.TransferSize = int64(len(buf))
				} else {
					file.Content = ([]byte)(nil)
				}
			}
			o.currentClientSession.File.ComputeTransferFields()
		}
	}

	for _, s := range o.disconnectedClients {
		// if serving to stdout
		if o.includeBody {
			if s.Request != nil {
				// then read in the body since it wasn't written to disk
				if err := s.Request.ReadBody(); err != nil {
					log.Error().Err(err).
						Msg("error reading request body buffer")
				}
			}
		} else {
			// otherwise, there's no point in showing the content again in stdout
			s.Request.Body = nil
		}

		if file := s.File; file != nil {
			if bf, ok := file.Content.(func() []byte); ok {
				if bf != nil {
					buf := bf()
					file.Content = buf
					file.TransferSize = int64(len(buf))
				} else {
					file.Content = ([]byte)(nil)
				}
			}
			s.File.ComputeTransferFields()
		}
	}

	if o.currentClientSession == nil && len(o.disconnectedClients) == 0 {
		return
	}

	report := Report{
		Success:  o.currentClientSession,
		Attempts: o.disconnectedClients,
	}

	signallingserver.SendReportToDiscoveryServer(ctx, newReportMessage(&report))

	if o.Format == "json" && !o.quiet {
		enc := json.NewEncoder(os.Stdout)
		if _, ok := o.FormatOpts["compact"]; !ok {
			enc.SetIndent("", "  ")
		}
		err := enc.Encode(report)
		if err != nil {
			log.Error().Err(err).
				Msg("error encoding json to stdout")
		}
	}
}
