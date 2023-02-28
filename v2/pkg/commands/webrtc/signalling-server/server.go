package signallingserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"sync"

	_ "embed"

	"github.com/raphaelreyna/oneshot/v2/pkg/events"
	"github.com/raphaelreyna/oneshot/v2/pkg/net/webrtc/sdp"
)

const maxBodySize = 1024 * 1024

//go:generate make webrtc-html
//go:embed htmlClientTemplate.html
var htmlClientTemplateFile string

func init() {
	if len(htmlClientTemplateFile) == 0 {
		panic("htmlClientTemplateFile not initialized")
	}
}

type server struct {
	htmlClientTemplate *template.Template

	os        *oneshotServer
	l         net.Listener
	pendingID int32
}

func newServer() (*server, error) {
	t, err := template.New("htmlClientTemplate").Parse(string(htmlClientTemplateFile))
	return &server{
		pendingID:          -1,
		htmlClientTemplate: t,
	}, err
}

func (s *server) run(ctx context.Context, signallingAddr, httpAddr string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	l, err := net.Listen("tcp", signallingAddr)
	if err != nil {
		return err
	}

	log.Printf("listening for signalling traffic on %s", signallingAddr)

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHTTP)
	hs := http.Server{
		Addr:    httpAddr,
		Handler: mux,
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	defer func() {
		wg.Wait()
		events.Stop(ctx)
	}()

	go func() {
		defer wg.Done()
		<-ctx.Done()
		log.Println("shutting down")

		ctx, cancel := context.WithTimeout(context.Background(), 5)
		defer cancel()

		if s.os != nil {
			if err := s.os.Close(); err != nil {
				if !errors.Is(err, net.ErrClosed) {
					log.Printf("error closing oneshot server: %v", err)
				}
			}
		}

		if err := hs.Shutdown(ctx); err != nil {
			log.Printf("error shutting down http server: %v", err)
		}

		log.Println("http service shutdown")

		if err := l.Close(); err != nil {
			log.Printf("error closing listener: %v", err)
		}

		log.Println("api service shutdown")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := hs.ListenAndServe(); err != nil {
			cancel()
			if err != http.ErrServerClosed {
				log.Printf("error serving http: %v", err)
			}
		}
	}()

	log.Printf("listening for http traffic on %s", httpAddr)

	s.l = l
	for {
		conn, err := s.l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			} else {
				log.Printf("error accepting connection: %v", err)
			}
			return fmt.Errorf("error accepting connection: %w", err)
		}

		if err := s.handleOneshotServer(ctx, conn); err != nil {
			log.Printf("error handling oneshot server: %v", err)
		}
	}
}

// handleOneshotServer handles a new connection to the signalling server.
// If the server is already in use, it will return a BUSY response.
// Otherwise, it will create a new oneshot server.
// handleOneshotServer takes over the connection and will close it when it is done.
func (s *server) handleOneshotServer(ctx context.Context, conn net.Conn) error {
	defer func() {
		log.Printf("closing connection: %v", conn.RemoteAddr())
		if err := conn.Close(); err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("error closing connection: %v", err)
			}
		}
	}()

	var err error
	if s.os != nil {
		if _, err = conn.Write([]byte("BUSY")); err != nil {
			return fmt.Errorf("error writing BUSY response: %w", err)
		}
		return nil
	}

	defer func() {
		s.os = nil
	}()

	if s.os, err = newOneshotServer(conn); err != nil {
		return fmt.Errorf("error creating new oneshot server: %w", err)
	}

	log.Printf("new oneshot server arrived: %v", conn.RemoteAddr())

	<-s.os.Done()

	log.Println("session ended")

	return nil
}

func (s *server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if s.os == nil {
		http.Error(w, "no oneshot server available", http.StatusServiceUnavailable)
		return
	}

	if r.Method == http.MethodGet {
		s.handleGet(w, r)
	} else if r.Method == http.MethodPost {
		s.handlePost(w, r)
	}
}

func (s *server) handleGet(w http.ResponseWriter, r *http.Request) {
	if -1 < s.pendingID {
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}

	if s.os.Arrival.BasicAuth != nil {
		// we need to do basic auth
		username, password, ok := r.BasicAuth()
		if ok {
			uHash := sha256.Sum256([]byte(username))
			pHash := sha256.Sum256([]byte(password))

			uMatch := subtle.ConstantTimeCompare(uHash[:], s.os.Arrival.BasicAuth.UsernameHash)
			pMatch := subtle.ConstantTimeCompare(pHash[:], s.os.Arrival.BasicAuth.PasswordHash)

			if uMatch == 0 || pMatch == 0 {
				w.Header().Set("WWW-Authenticate", `Basic realm="oneshot"; charset="UTF-8"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
	}

	s.pendingID = rand.Int31()
	offer, err := s.os.RequestOffer(r.Context(), s.pendingID)
	if err != nil {
		log.Printf("error requesting offer: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	offerBytes, err := offer.MarshalJSON()
	if err != nil {
		log.Printf("error marshaling offer: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	err = s.htmlClientTemplate.Execute(w, map[string]any{
		"Offer":     string(offerBytes),
		"SessionID": s.pendingID,
	})
	if err != nil {
		log.Printf("error writing response: %v", err)
	}

	log.Printf("sent offer for session id %d", s.pendingID)
}

func (s *server) handlePost(w http.ResponseWriter, r *http.Request) {
	if s.pendingID < 0 {
		log.Printf("received answer without pending offer")
		http.Error(w, "no pending offer", http.StatusServiceUnavailable)
		return
	}

	log.Printf("received answer for session id %d", s.pendingID)

	defer r.Body.Close()
	lr := io.LimitReader(r.Body, maxBodySize)
	body, err := io.ReadAll(lr)
	if err != nil {
		log.Printf("error reading body: %v", err)
		http.Error(w, "unable to read body", http.StatusInternalServerError)
		return
	}

	var answer struct {
		Answer string `json:"answer"`
		ID     int32  `json:"id"`
	}

	if err := json.Unmarshal(body, &answer); err != nil {
		log.Printf("error unmarshaling answer: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if answer.ID != s.pendingID {
		log.Printf("received answer with invalid id: %d (expected %d)", answer.ID, s.pendingID)
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	if err = s.os.SendAnswer(r.Context(), s.pendingID, sdp.Answer(answer.Answer)); err != nil {
		log.Printf("error sending answer: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Printf("answer sent for session id %d, closing connection to oneshot server", s.pendingID)

	s.pendingID = -1
	if err = s.os.Close(); err != nil {
		log.Printf("error closing oneshot server connection: %v", err)
	}
	s.os = nil
}