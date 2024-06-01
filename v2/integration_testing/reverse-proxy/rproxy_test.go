package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	itest "github.com/forestnode-io/oneshot/v2/integration_testing"
	"github.com/forestnode-io/oneshot/v2/pkg/output"
	"github.com/stretchr/testify/suite"
)

func TestBasicTestSuite(t *testing.T) {
	suite.Run(t, new(ts))
}

type ts struct {
	itest.TestSuite
}

func (suite *ts) Test_FROM_ANY_TO_StdoutTTY__StderrTTY() {
	wg := sync.WaitGroup{}
	wg.Add(1)
	s := http.Server{
		Addr: ":" + itest.MiscPortPool.Get(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("SUCCESS"))
		}),
	}
	go func() {
		defer wg.Done()
		s.ListenAndServe()
	}()

	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"rproxy", "http://localhost" + s.Addr}
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDOUT=true",
		"ONESHOT_TESTING_TTY_STDERR=true",
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	client := itest.RetryClient{
		Suite: &suite.Suite,
	}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port))
	suite.Require().NoError(err)
	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)
	resp.Body.Close()
	suite.Assert().Equal("SUCCESS", string(body))

	oneshot.Wait()

	s.Shutdown(context.Background())
	wg.Wait()

	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Equal("", string(stdout))

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
}

func (suite *ts) Test_tee_FROM_ANY_TO_StdoutTTY__StderrTTY() {
	wg := sync.WaitGroup{}
	wg.Add(1)
	s := http.Server{
		Addr: ":" + itest.MiscPortPool.Get(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("SUCCESS"))
		}),
	}
	go func() {
		defer wg.Done()
		s.ListenAndServe()
	}()

	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"rproxy", "--tee", "http://localhost" + s.Addr}
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDOUT=true",
		"ONESHOT_TESTING_TTY_STDERR=true",
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	client := itest.RetryClient{
		Suite: &suite.Suite,
	}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port))
	suite.Require().NoError(err)
	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)
	resp.Body.Close()
	suite.Assert().Equal("SUCCESS", string(body))

	oneshot.Wait()

	s.Shutdown(context.Background())
	wg.Wait()

	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Equal("SUCCESS", string(stdout))

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
}

func (suite *ts) Test_flags_FROM_ANY_TO_Stdout() {
	wg := sync.WaitGroup{}
	wg.Add(2)
	var (
		method                 string
		receivedRequestHeaders http.Header
	)
	s := http.Server{
		Addr: ":" + itest.MiscPortPool.Get(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			method = r.Method
			receivedRequestHeaders = r.Header.Clone()
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("SUCCESS"))
			wg.Done()
		}),
	}
	go func() {
		s.ListenAndServe()
		wg.Done()
	}()

	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"--output", "json",
		"rproxy",
		"--status-code", strconv.Itoa(http.StatusTeapot),
		"--request-header", "X-Test=123",
		"--response-header", "X-Test=321",
		"--method", "POST",
		"--match-host",
		"http://127.0.0.1" + s.Addr,
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{
		Suite: &suite.Suite,
	}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port))
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)
	suite.Assert().Equal(http.StatusTeapot, resp.StatusCode)
	resp.Body.Close()

	oneshot.Wait()

	s.Shutdown(context.Background())
	wg.Wait()

	suite.Assert().Equal("POST", method)

	// expect no dynamic out, only static output on stdout
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	var report output.Report
	err = json.Unmarshal(stdout, &report)
	suite.Assert().NoError(err)
	suite.Assert().NotNil(report.Success)
	suite.Assert().Equal(0, len(report.Attempts))

	req := report.Success.Request
	suite.Assert().Equal("GET", req.Method)
	suite.Assert().Equal(fmt.Sprintf("127.0.0.1:%s", oneshot.Port), req.Host)
	suite.Assert().Equal("123", receivedRequestHeaders.Get("X-Test"))
	suite.Assert().Equal("321", resp.Header.Get("X-Test"))
}

func (suite *ts) Test_FROM_ANY_TO_Stdout__JSON() {
	wg := sync.WaitGroup{}
	wg.Add(1)
	s := http.Server{
		Addr: ":" + itest.MiscPortPool.Get(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("SUCCESS"))
		}),
	}
	go func() {
		defer wg.Done()
		s.ListenAndServe()
	}()

	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"--output", "json", "rproxy", "http://localhost" + s.Addr}
	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{
		Suite: &suite.Suite,
	}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port))
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	oneshot.Wait()

	s.Shutdown(context.Background())
	wg.Wait()

	// expect no dynamic out, only static output on stdout
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	var report output.Report
	err = json.Unmarshal(stdout, &report)
	suite.Assert().NoError(err)
	suite.Assert().NotNil(report.Success)
	suite.Assert().Equal(0, len(report.Attempts))

	req := report.Success.Request
	suite.Assert().Equal("GET", req.Method)
	suite.Assert().Equal("HTTP/1.1", req.Protocol)
	suite.Assert().Equal(fmt.Sprintf("127.0.0.1:%s", oneshot.Port), req.Host)

	response := report.Success.Response
	suite.Assert().Equal(http.StatusOK, response.StatusCode)
	suite.Require().NotNil(response.Header)
	suite.Require().NotNil(response.Body)
	body := response.Body.(string)
	bodyBytes, err := base64.StdEncoding.DecodeString(body)
	suite.Require().NoError(err)
	suite.Assert().Equal("SUCCESS", string(bodyBytes))

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
}

func (suite *ts) Test_MultipleClients() {
	swg := sync.WaitGroup{}
	swg.Add(2)
	requests := 0
	s := http.Server{
		Addr: ":" + itest.MiscPortPool.Get(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("SUCCESS"))
			swg.Done()
		}),
	}
	go func() {
		defer swg.Done()
		s.ListenAndServe()
	}()

	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"rproxy", "--tee", "http://localhost" + s.Addr}
	oneshot.Start()
	defer oneshot.Cleanup()

	m := sync.Mutex{}
	c := sync.NewCond(&m)

	responses := make(chan int, runtime.NumCPU())
	wg := sync.WaitGroup{}
	for i := 1; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func(index int) {
			c.L.Lock()
			c.Wait()
			c.L.Unlock()

			payload := []byte("SUCCESS")
			resp, _ := http.Post(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port), "text/plain", bytes.NewReader(payload))
			if resp != nil {
				if resp.Body != nil {
					resp.Body.Close()
				}
				responses <- resp.StatusCode
			} else {
				responses <- 0
			}
			wg.Done()
		}(i)
	}
	time.Sleep(500 * time.Millisecond)
	c.L.Lock()
	c.Broadcast()
	c.L.Unlock()

	wg.Wait()
	close(responses)

	oks := 0
	gones := 0
	for code := range responses {
		if code == 200 {
			oks++
		} else if code == http.StatusGone {
			gones++
		}
	}
	suite.Assert().Equal(1, oks)
	suite.Assert().Equal(runtime.NumCPU()-2, gones)

	suite.Assert().Equal(1, requests)

	oneshot.Wait()
	s.Shutdown(context.Background())
	swg.Wait()

	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Equal("SUCCESS", string(stdout))

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
}
