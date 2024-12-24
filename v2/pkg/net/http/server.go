package http

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/forestnode-io/oneshot/v2/pkg/events"
	oneshotnet "github.com/forestnode-io/oneshot/v2/pkg/net"
	"github.com/forestnode-io/oneshot/v2/pkg/output"
	"github.com/forestnode-io/oneshot/v2/pkg/ssl"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

const shutdownTimeout = 500 * time.Millisecond

type _wr struct {
	w    *responseWriter
	r    *http.Request
	done func()
}

type Server struct {
	server http.Server

	PreSuccessHandler  http.HandlerFunc
	PostSuccessHandler http.HandlerFunc

	TLSCert, TLSKey string
	Timeout         time.Duration

	ExitOnFail bool

	queue chan _wr
}

type ServerConfig struct {
	PreSuccessHandler  http.HandlerFunc
	PostSuccessHandler http.HandlerFunc
	Middleware         []Middleware
	TLSConfig          *tls.Config
	Timeout            time.Duration
	ExitOnFail         bool
}

func NewServer(ctx context.Context, config ServerConfig) *Server {
	s := Server{
		Timeout:            config.Timeout,
		ExitOnFail:         config.ExitOnFail,
		PreSuccessHandler:  config.PreSuccessHandler,
		PostSuccessHandler: config.PostSuccessHandler,

		queue: make(chan _wr, runtime.NumCPU()),

		server: http.Server{
			TLSConfig: config.TLSConfig,
			// TODO(raphaelreyna): add logging
			ErrorLog: log.New(io.Discard, "", 0),
		},
	}
	s.server.BaseContext = func(l net.Listener) context.Context {
		return ctx
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		wr := _wr{
			w: &responseWriter{ResponseWriter: w},
			r: r,
		}

		// give the handler a way of telling us it's done
		doneChan := make(chan struct{})
		wr.done = func() {
			close(doneChan)
		}

		// give the request to the worker(s)
		s.queue <- wr
		// wait for the worker to tell us it's done
		<-doneChan
	}

	// apply middleware
	for _, mw := range config.Middleware {
		handler = mw(handler)
	}

	r := mux.NewRouter()
	r.PathPrefix("/").HandlerFunc(handler)
	s.server.Handler = r

	return &s
}

// Serve starts the server and blocks until the context is canceled or a handler raises a success event.
// Serve waits for all workers to finish before returning.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	var (
		log             = zerolog.Ctx(ctx)
		wg              = sync.WaitGroup{}
		shutdownErrChan = make(chan error)
		usingTLS        = s.server.TLSConfig != nil
		shuttingDown    bool
		shuttingDownMu  sync.Mutex
	)

	shutdown := func(ctx context.Context) {
		shuttingDownMu.Lock()
		defer shuttingDownMu.Unlock()
		if shuttingDown {
			return
		}
		shuttingDown = true

		log.Debug().Msg("shutting down HTTP server")
		shutdownErrChan <- s.server.Shutdown(ctx)
		log.Debug().Msg("finished shutting down HTTP server")
	}
	if l == nil {
		shutdown = func(_ context.Context) {
			shuttingDownMu.Lock()
			defer shuttingDownMu.Unlock()
			if shuttingDown {
				return
			}
			shuttingDown = true

			shutdownErrChan <- nil
		}
	}

	postSuccWorker := func() {
		for wr := range s.queue {
			s.PostSuccessHandler(wr.w, wr.r)
			wr.done()
		}
		wg.Done()
	}

	type ts interface {
		TriggersShutdown()
	}

	preSuccWorker := func() {
		for wr := range s.queue {
			s.PreSuccessHandler(wr.w, wr.r.WithContext(ctx))

			if !wr.w.ignoreOutcome && (events.Succeeded(ctx) || s.ExitOnFail) {
				tsw, ok := wr.w.ResponseWriter.(ts)
				if ok {
					tsw.TriggersShutdown()
				}

				cpuCount := runtime.NumCPU()
				wg.Add(cpuCount)
				for i := 0; i < cpuCount; i++ {
					go postSuccWorker()
				}

				ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
				shutdown(ctx)
				cancel()

				wr.done()
				return
			} else {
				wr.done()
			}
		}
	}

	go preSuccWorker()
	if 0 < s.Timeout {
		lt := oneshotnet.NewListenerTimer(l, s.Timeout)
		l = lt
		go func() {
			select {
			case <-lt.C:
				events.SetExitCode(ctx, events.ExitCodeTimeoutFailure)
			case <-ctx.Done():
			}
			ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			shutdown(ctx)
		}()
	} else {
		go func() {
			<-ctx.Done()
			ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			shutdown(ctx)
		}()
	}

	var err error
	if l != nil {
		if usingTLS {
			log.Info().
				Str("cert", s.TLSCert).
				Str("key", s.TLSKey).
				Msg("serving HTTPS")

			tlsListener, err := ssl.UpgradeListener(l, s.server.TLSConfig)
			if err == nil {
				err = s.server.Serve(tlsListener)
				err = output.WrapPrintable(err)
			} else {
				err = output.WrapPrintable(err)
			}
		} else {
			log.Info().
				Msg("serving HTTP")

			err = s.server.Serve(l)
			err = output.WrapPrintable(err)
		}
		if err = cleanServerShutdownErr(err); err != nil {
			log.Error().Err(err).
				Msg("HTTP(S) server error")
		}
	} else {
		log.Info().Msg("only listenening for HTTP traffic over webRTC")
	}

	// wait for the server to shutdown
	log.Debug().Msg("waiting for HTTP(S) server to shutdown")
	err = <-shutdownErrChan
	log.Debug().Msg("done waiting for HTTP(S) server to shutdown")

	close(s.queue)

	// wait for the workers to finish
	log.Debug().Msg("waiting for workers to finish")
	wg.Wait()
	log.Debug().Msg("done waiting for workers to finish")

	return cleanServerShutdownErr(err)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.server.Handler.ServeHTTP(w, r)
}

func cleanServerShutdownErr(err error) error {
	if errors.Is(err, http.ErrServerClosed) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return nil
	}

	return output.WrapPrintable(err)
}

type responseWriter struct {
	http.ResponseWriter
	wroteHeader   bool
	ignoreOutcome bool
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *responseWriter) WriteHeader(code int) {
	w.wroteHeader = true
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriter) IgnoreOutcome() {
	w.ignoreOutcome = true
}

type ResponseWriter interface {
	http.ResponseWriter
	IgnoreOutcome()
}
