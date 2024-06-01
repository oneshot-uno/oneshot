package main

import (
	"io"
	"net/http"
	"syscall"
	"testing"
	"time"

	itest "github.com/forestnode-io/oneshot/v2/integration_testing"
	"github.com/stretchr/testify/suite"
)

func TestBasicTestSuite(t *testing.T) {
	suite.Run(t, new(ts))
}

type ts struct {
	itest.TestSuite
}

func (suite *ts) Test_Signal_SIGINT() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"receive"}
	oneshot.Start()
	defer oneshot.Cleanup()

	time.Sleep(500 * time.Millisecond)
	err := oneshot.Cmd.Process.Signal(syscall.SIGINT)
	suite.Require().NoError(err)

	oneshot.Wait()
}

func (suite *ts) Test_timeoutFlag() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"receive", "--timeout", "1s"}
	oneshot.Start()
	defer oneshot.Cleanup()

	timer := time.AfterFunc(time.Second+500*time.Millisecond, func() {
		_ = oneshot.Cmd.Process.Signal(syscall.SIGINT)
		suite.Fail("timeout did not work")
	})
	defer timer.Stop()

	oneshot.Wait()
}

func (suite *ts) Test_Basic_Auth() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"send", "--username", "oneshot", "--password", "hunter2"}
	oneshot.Stdin = itest.EOFReader([]byte("SUCCESS"))
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDIN=true",
		"ONESHOT_TESTING_TTY_STDOUT=true",
		"ONESHOT_TESTING_TTY_STDERR=true",
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	client := itest.RetryClient{}
	resp, err := client.Get("http://127.0.0.1:" + oneshot.Port)
	suite.Require().NoError(err)
	suite.Assert().Equal(resp.StatusCode, http.StatusUnauthorized)

	req, err := http.NewRequest("GET", "http://127.0.0.1:"+oneshot.Port, nil)
	suite.Require().NoError(err)
	req.SetBasicAuth("oneshot", "hunter2")
	resp, err = client.Do(req)
	suite.Require().NoError(err)
	suite.Assert().Equal(resp.StatusCode, http.StatusOK)

	body, err := io.ReadAll(resp.Body)
	suite.Assert().NoError(err)
	resp.Body.Close()
	suite.Assert().Equal(string(body), "SUCCESS")

	oneshot.Wait()
}
