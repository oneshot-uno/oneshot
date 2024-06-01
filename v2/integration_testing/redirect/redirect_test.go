package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
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

func (suite *ts) Test_StdinTTY_StderrTTY() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"redirect", "https://github.com"}
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDOUT=true",
		"ONESHOT_TESTING_TTY_STDERR=true",
	}
	oneshot.Start()

	client := itest.RetryClient{}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port))
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)
	suite.Assert().Equal(http.StatusTemporaryRedirect, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)
	suite.Assert().Contains(string(body), "https://github.com")

	oneshot.Wait()
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Equal("", string(stdout))

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
}

func (suite *ts) Test_JSON() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"redirect", "--output", "json", "https://github.com"}
	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s?q=1", oneshot.Port))
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusTemporaryRedirect, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	suite.Assert().NoError(err)
	resp.Body.Close()
	suite.Assert().Contains(string(body), "https://github.com")

	oneshot.Wait()
	// expect no dynamic out, only static output on stdout
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	var report output.Report
	err = json.Unmarshal(stdout, &report)
	suite.Assert().NoError(err)
	suite.Assert().NotNil(report.Success)
	suite.Assert().Equal(0, len(report.Attempts))

	req := report.Success.Request
	suite.Require().NotNil(req)

	suite.Require().Equal("GET", req.Method)
	suite.Assert().Equal("HTTP/1.1", req.Protocol)
	suite.Assert().Equal(map[string][]string{
		"Accept-Encoding": {"gzip"},
		"User-Agent":      {"Go-http-client/1.1"},
	}, req.Header)
	suite.Assert().Equal(fmt.Sprintf("127.0.0.1:%s", oneshot.Port), req.Host)
	suite.Assert().Empty(req.Trailer)
	suite.Assert().NotEmpty(req.RemoteAddr)
	suite.Assert().Equal("/?q=1", req.RequestURI)
	suite.Assert().Equal("/", req.Path)
	suite.Assert().Equal(map[string][]string{
		"q": {"1"},
	}, req.Query)

	suite.Require().Nil(report.Success.File)

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
}

func (suite *ts) Test_MultipleClients() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"redirect", "https://github.com"}
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDOUT=true",
		"ONESHOT_TESTING_TTY_STDERR=true",
	}
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

			resp, _ := http.Get(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port))
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
		} else {
			gones++
		}
	}
	suite.Assert().Equal(1, oks)
	suite.Assert().Equal(runtime.NumCPU()-2, gones)

	oneshot.Wait()
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Equal(string(stdout), "")

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
}
