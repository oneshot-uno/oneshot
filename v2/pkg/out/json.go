package out

import (
	"context"
	"encoding/json"
	"os"

	"github.com/raphaelreyna/oneshot/v2/pkg/events"
)

func runJSON(ctx context.Context, o *output) {
	for {
		select {
		case <-ctx.Done():
			_json_handleContextDone(ctx, o)
			return
		case event := <-o.events:
			_json_handleEvent(o, event)
		}
	}
}

func _json_handleEvent(o *output, e events.Event) {
	switch event := e.(type) {
	case *events.ClientDisconnected:
		o.cls = append(o.cls, o.currentClientSession)
		o.currentClientSession = nil
	case *events.HTTPRequest:
		o.currentClientSession = &clientSession{
			Request: event,
		}
	case *events.File:
		if o.currentClientSession != nil {
			o.currentClientSession.File = event
			if bf, ok := o.currentClientSession.File.Content.(func() []byte); ok {
				// if the user want to receive to stdout then the received content wont be saved to disk
				if o.servingToStdout {
					// so we include it in the json report which is going to stdout
					o.currentClientSession.File.Content = bf()
				} else {
					// otherwise, dump the contents
					// TODO(raphaelreyna): look into if this is ever even not nil
					_ = bf()
					o.currentClientSession.File.Content = nil
				}
			}
		}
	}
}

func _json_handleContextDone(ctx context.Context, o *output) {
	if err := events.GetCancellationError(ctx); err != nil {
		// TODO(raphaelreyna): handle this more gracefully
		panic(err)
	}

	// if serving to stdout
	if o.servingToStdout {
		// then read in the body since it wasnt written to disk
		if err := o.currentClientSession.Request.ReadBody(); err != nil {
			// TODO(raphaelreyna): handle this more gracefully
			panic(err)
		}
	} else {
		// otherwise, theres no point in showing the content again in stdout
		o.currentClientSession.Request.Body = nil
	}
	o.currentClientSession.File.ComputeTransferFields()

	for _, s := range o.cls {
		// if serving to stdout
		if o.servingToStdout {
			// then read in the body since it wasnt written to disk
			if err := s.Request.ReadBody(); err != nil {
				panic(err)
			}
		} else {
			// otherwise, theres no point in showing the content again in stdout
			s.Request.Body = nil
		}
		s.File.ComputeTransferFields()
	}
	err := json.NewEncoder(os.Stdout).Encode(report{
		Success:  o.currentClientSession,
		Attempts: o.cls,
	})
	if err != nil {
		// TODO(raphaelreyna): handle this more gracefully
		panic(err)
	}
}