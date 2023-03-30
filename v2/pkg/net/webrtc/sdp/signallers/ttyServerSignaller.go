package signallers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/muesli/cancelreader"
	"github.com/pion/webrtc/v3"
	"github.com/raphaelreyna/oneshot/v2/pkg/net/webrtc/sdp"
)

type ttyServerSignaller struct {
	cancel func()
	config *webrtc.Configuration
}

func NewTTYServerSignaller(config *webrtc.Configuration) ServerSignaller {
	return &ttyServerSignaller{
		config: config,
	}
}

func (s *ttyServerSignaller) Start(ctx context.Context, handler RequestHandler) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	stdin, err := cancelreader.NewReader(os.Stdin)
	if err != nil {
		return fmt.Errorf("unable to create cancelable reader: %w", err)
	}
	defer stdin.Close()
	go func() {
		<-ctx.Done()
		stdin.Cancel()
	}()

	id := 0
	for s.cancel != nil {
		handler.HandleRequest(ctx, strconv.Itoa(id), s.config, s.answerOffer)
		id++

	READ_SECTION:
		var char = make([]byte, 1)
		if _, err := stdin.Read(char); err != nil {
			return fmt.Errorf("unable to read from stdin: %w", err)
		}

		if char[0] == '\n' {
			continue
		} else {
			goto READ_SECTION
		}
	}
	return nil
}

func (s *ttyServerSignaller) Shutdown() error {
	s.cancel()
	s.cancel = nil
	return nil
}

func (s *ttyServerSignaller) answerOffer(ctx context.Context, id string, offer sdp.Offer) (sdp.Answer, error) {
	fmt.Printf("offer: \n%s\n", string(offer))
	fmt.Println("Please paste the client SDP below and press enter:")

	stdin, err := cancelreader.NewReader(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("unable to create cancelable reader: %w", err)
	}
	defer stdin.Close()
	go func() {
		<-ctx.Done()
		stdin.Cancel()
	}()

	r := bufio.NewScanner(stdin)
	r.Split(bufio.ScanLines)

	var line string
	if r.Scan() {
		line = r.Text()
	} else {
		if err := r.Err(); err != nil {
			return "", fmt.Errorf("unable to read from stdin: %w", err)
		}
	}

	var sd webrtc.SessionDescription
	if err := json.Unmarshal([]byte(line), &sd); err != nil {
		return "", err
	}

	return sdp.Answer(sd.SDP), nil
}
