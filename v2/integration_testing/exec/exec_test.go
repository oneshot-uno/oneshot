package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
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
	oneshot.Args = []string{"exec", "go", "env", "GOOS"}
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDIN=true",
		"ONESHOT_TESTING_TTY_STDOUT=true",
		"ONESHOT_TESTING_TTY_STDERR=true",
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{}
	addr := fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port)
	resp, err := client.Get(addr)
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	suite.Assert().NoError(err)
	resp.Body.Close()

	output := strings.ReplaceAll(string(body), "\n", "")
	suite.Assert().Equal(runtime.GOOS, output)

	oneshot.Wait()
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Equal("", string(stdout))

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
}

func (suite *ts) Test_JSON() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"exec", "--output", "json", "go", "env", "GOOS"}
	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{}
	addr := fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port)
	resp, err := client.Get(addr + "/?q=1")
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	suite.Assert().NoError(err)
	resp.Body.Close()
	suite.Assert().Equal(runtime.GOOS+"\n", string(body))

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
	suite.Assert().Equal("127.0.0.1:"+oneshot.Port, req.Host)
	suite.Assert().Empty(req.Trailer)
	suite.Assert().NotEmpty(req.RemoteAddr)
	suite.Assert().Equal("/?q=1", req.RequestURI)
	suite.Assert().Equal("/", req.Path)
	suite.Assert().Equal(map[string][]string{
		"q": {"1"},
	}, req.Query)

	file := report.Success.File
	suite.Require().NotNil(file)
	now := time.Now()
	suite.Assert().Equal(int64(0), file.Size)
	suite.Assert().Less(int64(0), file.TransferSize)
	suite.Assert().WithinDuration(now, file.TransferStartTime, 5*time.Second)
	suite.Assert().WithinDuration(now, file.TransferEndTime, 5*time.Second)
	suite.Assert().Less(time.Duration(0), file.TransferDuration)
	suite.Assert().NotNil(file.Content)
	suite.Assert().Empty(file.Name)
	suite.Assert().Empty(file.Path)
	suite.Assert().Empty(file.MIME)

	content, err := base64.StdEncoding.DecodeString(file.Content.(string))
	suite.Require().NoError(err)
	suite.Assert().Equal(runtime.GOOS+"\n", string(content))

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
}

func (suite *ts) Test_MultipleClients() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"exec", "go", "env", "GOOS"}
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDIN=true",
		"ONESHOT_TESTING_TTY_STDOUT=true",
		"ONESHOT_TESTING_TTY_STDERR=true",
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	m := sync.Mutex{}
	c := sync.NewCond(&m)

	responses := make(chan int, runtime.NumCPU())
	wg := sync.WaitGroup{}

	addr := fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port)
	for i := 1; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func(index int) {
			c.L.Lock()
			c.Wait()
			c.L.Unlock()

			resp, _ := http.Get(addr)
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

	oneshot.Wait()
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Contains(string(stdout), "")

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
}
