package events

import (
	"bytes"
	"io"
	"net/http"
)

type HTTPRequest struct {
	Method     string              `json:",omitempty"`
	RequestURI string              `json:",omitempty"`
	Path       string              `json:",omitempty"`
	Query      map[string][]string `json:",omitempty"`
	Protocol   string              `json:",omitempty"`
	Header     map[string][]string `json:",omitempty"`
	Host       string              `json:",omitempty"`
	Trailer    map[string][]string `json:",omitempty"`
	RemoteAddr string              `json:",omitempty"`

	Body any `json:",omitempty"`

	body func() ([]byte, error) `json:"-"`
}

// ReadBody reads in the http requests body by calling body() if its not nil.
// the body func just reads in a buffered copy of the body; it will have already
// been read from the client point of view.
func (hr *HTTPRequest) ReadBody() error {
	bf := hr.body
	if bf == nil || hr.Body != nil {
		return nil
	}

	body, err := bf()
	if err != nil {
		return err
	}

	if len(body) == 0 {
		return nil
	}

	hr.Body = body

	return nil
}

// newHTTPRequest_WithBody replaces the requests body with a tee reader that copies the data into a byte buffer.
// This allows for the body to be written out later in a report should we need to.
func NewHTTPRequest(r *http.Request, wrapper func(io.Reader) io.Reader) *HTTPRequest {
	ht := HTTPRequest{
		Method:     r.Method,
		RequestURI: r.RequestURI,
		Path:       r.URL.Path,
		Query:      r.URL.Query(),
		Protocol:   r.Proto,
		Header:     r.Header.Clone(),
		Host:       r.Host,
		Trailer:    r.Trailer.Clone(),
		RemoteAddr: r.RemoteAddr,
	}

	if r.Body == nil {
		return &ht
	}

	buf := bytes.NewBuffer(nil)
	r.Body = io.NopCloser(io.TeeReader(r.Body, buf))
	ht.body = func() ([]byte, error) {
		if wrapper != nil {
			return io.ReadAll(wrapper(buf))
		} else {
			return buf.Bytes(), nil
		}
	}

	return &ht
}

func (*HTTPRequest) isEvent() {}

type HTTPResponse struct {
	StatusCode int         `json:",omitempty"`
	Header     http.Header `json:",omitempty"`
	Body       any         `json:",omitempty"`
}

func (hr *HTTPResponse) ReadBody() error {
	if hr.Body != nil {
		return nil
	}

	bf, ok := hr.Body.(func() []byte)
	if !ok {
		return nil
	}

	body := bf()
	if len(body) == 0 {
		hr.Body = nil
		return nil
	}

	hr.Body = body

	return nil
}

func (*HTTPResponse) isEvent() {}
